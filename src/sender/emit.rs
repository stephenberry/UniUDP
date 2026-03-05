use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[cfg(feature = "tokio")]
use tokio::net::UdpSocket as TokioUdpSocket;
#[cfg(feature = "tokio")]
use tokio::time::sleep as tokio_sleep;

use crate::error::{EncodeContext, Result, UniUdpError, ValidationContext};
use crate::fec::{pack_rs_parity_field, FecMode};
use crate::header_validation::validate_header_invariants;
use crate::packet::{write_header, PacketEncodeSecurity};
use crate::types::{MessageKey, PacketAuth, PacketHeader, HEADER_LENGTH};

use super::plan::{ParityContext, SendPlan};

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
/// Reusable sender-side scratch buffers for high-throughput paths.
///
/// Reuse one instance across repeated sends to avoid per-call packet/parity
/// buffer allocations.  The RS encoder is cached so that its internal Galois
/// field tables are not rebuilt on every parity group.
pub struct SendScratch {
    packet_buffer: Vec<u8>,
    rs_data_buffers: Vec<Vec<u8>>,
    rs_parity_buffers: Vec<Vec<u8>>,
    rs_encoder: Option<reed_solomon_erasure::galois_8::ReedSolomon>,
}

impl SendScratch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_for_plan(&mut self, plan: &SendPlan) {
        let packet_len = HEADER_LENGTH + plan.chunk_size;
        if self.packet_buffer.len() != packet_len {
            self.packet_buffer.resize(packet_len, 0_u8);
        }
        match plan.fec_mode {
            FecMode::None => {}
            FecMode::ReedSolomon {
                data_shards,
                parity_shards,
            } => {
                let ds = usize::from(data_shards);
                let ps = usize::from(parity_shards);
                self.rs_data_buffers.resize_with(ds, Vec::new);
                for buf in &mut self.rs_data_buffers[..ds] {
                    buf.resize(plan.chunk_size, 0_u8);
                }
                self.rs_parity_buffers.resize_with(ps, Vec::new);
                for buf in &mut self.rs_parity_buffers[..ps] {
                    buf.resize(plan.chunk_size, 0_u8);
                }
                // Cache the RS encoder so it is not rebuilt per parity group.
                let needs_rebuild = self.rs_encoder.as_ref().map_or(true, |e| {
                    e.data_shard_count() != ds || e.parity_shard_count() != ps
                });
                if needs_rebuild {
                    self.rs_encoder = reed_solomon_erasure::galois_8::ReedSolomon::new(ds, ps).ok();
                }
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct EmitFailure {
    pub(super) key: MessageKey,
    pub(super) packets_sent: usize,
    pub(super) error: Box<UniUdpError>,
}

impl EmitFailure {
    fn new(key: MessageKey, packets_sent: usize, error: UniUdpError) -> Self {
        Self {
            key,
            packets_sent,
            error: Box::new(error),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EmitContext<'a> {
    socket: &'a UdpSocket,
    destination: SocketAddr,
    packet_auth: Option<&'a PacketAuth>,
    delay: Duration,
}

struct EmitRuntime<'a> {
    buffer: &'a mut [u8],
    pace: &'a mut dyn FnMut(Duration),
    packets_sent: &'a mut usize,
}

#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy)]
struct TokioEmitContext<'a> {
    socket: &'a TokioUdpSocket,
    destination: SocketAddr,
    packet_auth: Option<&'a PacketAuth>,
    delay: Duration,
}

#[cfg(feature = "tokio")]
struct TokioEmitRuntime<'a> {
    buffer: &'a mut [u8],
    packets_sent: &'a mut usize,
}

pub(super) fn emit_with_socket_and_pacer_with_scratch<F>(
    socket: &UdpSocket,
    destination: SocketAddr,
    data: &[u8],
    packet_auth: Option<&PacketAuth>,
    plan: SendPlan,
    mut pace: F,
    scratch: &mut SendScratch,
) -> std::result::Result<MessageKey, EmitFailure>
where
    F: FnMut(Duration),
{
    scratch.ensure_for_plan(&plan);
    let emit_context = EmitContext {
        socket,
        destination,
        packet_auth,
        delay: plan.delay,
    };
    let parity_context = plan.parity_context();
    let mut packets_sent = 0_usize;
    let mut runtime = EmitRuntime {
        buffer: scratch.packet_buffer.as_mut_slice(),
        pace: &mut pace,
        packets_sent: &mut packets_sent,
    };

    // Keep sync/async loops structurally parallel for readability.
    for chunk_idx in 0..plan.total_chunks {
        let (start_idx, stop_idx) = plan.chunk_bounds(chunk_idx);
        let payload_len = stop_idx.saturating_sub(start_idx);
        let payload_slice = &data[start_idx..stop_idx];
        let mut header = plan.data_header(chunk_idx, payload_len);

        if let Err(error) = emit_attempts(&emit_context, &mut runtime, &mut header, payload_slice) {
            return Err(EmitFailure::new(plan.key, *runtime.packets_sent, error));
        }
        match plan.fec_mode {
            FecMode::None => {}
            FecMode::ReedSolomon { .. } => {
                let encoder = match scratch.rs_encoder.as_ref() {
                    Some(e) => e,
                    None => {
                        return Err(EmitFailure::new(
                            plan.key,
                            *runtime.packets_sent,
                            UniUdpError::encode(
                                EncodeContext::Packet,
                                "RS encoder not initialized",
                            ),
                        ));
                    }
                };
                let mut rs = RsScratchRef {
                    data_buffers: &mut scratch.rs_data_buffers,
                    parity_buffers: &mut scratch.rs_parity_buffers,
                    encoder,
                };
                if let Err(error) = maybe_emit_rs_parity_group(
                    &parity_context,
                    chunk_idx,
                    payload_slice,
                    &mut rs,
                    &emit_context,
                    &mut runtime,
                ) {
                    return Err(EmitFailure::new(plan.key, *runtime.packets_sent, error));
                }
            }
        }
    }

    Ok(plan.key)
}

#[cfg(feature = "tokio")]
pub(super) async fn emit_with_tokio_socket_with_scratch(
    socket: &TokioUdpSocket,
    destination: SocketAddr,
    data: &[u8],
    packet_auth: Option<&PacketAuth>,
    plan: SendPlan,
    scratch: &mut SendScratch,
) -> std::result::Result<MessageKey, EmitFailure> {
    scratch.ensure_for_plan(&plan);
    let mut packets_sent = 0_usize;
    let emit_context = TokioEmitContext {
        socket,
        destination,
        packet_auth,
        delay: plan.delay,
    };
    let parity_context = plan.parity_context();
    let mut runtime = TokioEmitRuntime {
        buffer: scratch.packet_buffer.as_mut_slice(),
        packets_sent: &mut packets_sent,
    };

    for chunk_idx in 0..plan.total_chunks {
        let (start_idx, stop_idx) = plan.chunk_bounds(chunk_idx);
        let payload_len = stop_idx.saturating_sub(start_idx);
        let payload_slice = &data[start_idx..stop_idx];
        let mut header = plan.data_header(chunk_idx, payload_len);

        if let Err(error) =
            emit_attempts_async(&emit_context, &mut runtime, &mut header, payload_slice).await
        {
            return Err(EmitFailure::new(plan.key, *runtime.packets_sent, error));
        }

        match plan.fec_mode {
            FecMode::None => {}
            FecMode::ReedSolomon { .. } => {
                let encoder = match scratch.rs_encoder.as_ref() {
                    Some(e) => e,
                    None => {
                        return Err(EmitFailure::new(
                            plan.key,
                            *runtime.packets_sent,
                            UniUdpError::encode(
                                EncodeContext::Packet,
                                "RS encoder not initialized",
                            ),
                        ));
                    }
                };
                let mut rs = RsScratchRef {
                    data_buffers: &mut scratch.rs_data_buffers,
                    parity_buffers: &mut scratch.rs_parity_buffers,
                    encoder,
                };
                if let Err(error) = maybe_emit_rs_parity_group_async(
                    &parity_context,
                    chunk_idx,
                    payload_slice,
                    &mut rs,
                    &emit_context,
                    &mut runtime,
                )
                .await
                {
                    return Err(EmitFailure::new(plan.key, *runtime.packets_sent, error));
                }
            }
        }
    }

    Ok(plan.key)
}

fn write_packet_into(
    buffer: &mut [u8],
    header: &PacketHeader,
    payload: &[u8],
    packet_auth: Option<&PacketAuth>,
) -> Result<usize> {
    if payload.len() > usize::from(header.chunk_size) {
        return Err(UniUdpError::validation(
            ValidationContext::PacketWrite,
            "payload is longer than chunk_size",
        ));
    }
    if buffer.len() < HEADER_LENGTH + payload.len() {
        return Err(UniUdpError::validation(
            ValidationContext::PacketWrite,
            "packet buffer too small",
        ));
    }

    let mut header = *header;
    header.payload_len = payload.len() as u16;
    if let Err(violation) = validate_header_invariants(&header, payload.len()) {
        return Err(UniUdpError::validation_detail(
            ValidationContext::PacketWrite,
            violation.message,
            violation.field,
            violation.expected,
            violation.actual,
        ));
    }
    write_header(
        &mut buffer[..HEADER_LENGTH],
        &header,
        payload,
        PacketEncodeSecurity { packet_auth },
    )?;
    if !payload.is_empty() {
        buffer[HEADER_LENGTH..HEADER_LENGTH + payload.len()].copy_from_slice(payload);
    }
    Ok(HEADER_LENGTH + payload.len())
}

fn emit_attempts(
    context: &EmitContext<'_>,
    runtime: &mut EmitRuntime<'_>,
    header: &mut PacketHeader,
    payload: &[u8],
) -> Result<()> {
    for attempt in 1..=header.redundancy {
        header.attempt = attempt;
        let packet_len = write_packet_into(runtime.buffer, header, payload, context.packet_auth)?;
        if *runtime.packets_sent > 0 && !context.delay.is_zero() {
            (runtime.pace)(context.delay);
        }
        let sent = context
            .socket
            .send_to(&runtime.buffer[..packet_len], context.destination)?;
        if sent != packet_len {
            return Err(UniUdpError::encode(
                EncodeContext::Packet,
                "short UDP datagram send",
            ));
        }
        *runtime.packets_sent = (*runtime.packets_sent).saturating_add(1);
    }
    Ok(())
}

#[cfg(feature = "tokio")]
async fn emit_attempts_async(
    context: &TokioEmitContext<'_>,
    runtime: &mut TokioEmitRuntime<'_>,
    header: &mut PacketHeader,
    payload: &[u8],
) -> Result<()> {
    for attempt in 1..=header.redundancy {
        header.attempt = attempt;
        let packet_len = write_packet_into(runtime.buffer, header, payload, context.packet_auth)?;
        if *runtime.packets_sent > 0 && !context.delay.is_zero() {
            tokio_sleep(context.delay).await;
        }
        let sent = context
            .socket
            .send_to(&runtime.buffer[..packet_len], context.destination)
            .await?;
        if sent != packet_len {
            return Err(UniUdpError::encode(
                EncodeContext::Packet,
                "short UDP datagram send",
            ));
        }
        *runtime.packets_sent = (*runtime.packets_sent).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared parity header builder
// ---------------------------------------------------------------------------

fn build_parity_header(ctx: &ParityContext, group_start: usize, fec_field: u16) -> PacketHeader {
    let chunk_index =
        u32::try_from(group_start).expect("parity group_start validated in send plan");
    let total_chunks =
        u32::try_from(ctx.total_chunks).expect("total_chunks validated in send plan");
    let message_length =
        u32::try_from(ctx.message_length).expect("message_length validated in send plan");
    PacketHeader {
        sender_id: ctx.sender_id,
        message_id: ctx.message_id,
        session_nonce: ctx.session_nonce,
        chunk_index,
        total_chunks,
        message_length,
        chunk_size: ctx.chunk_size_u16,
        payload_len: ctx.chunk_size_u16,
        redundancy: ctx.redundancy_u16,
        attempt: 0,
        fec_field,
    }
}

// ---------------------------------------------------------------------------
// Reed-Solomon parity emission
// ---------------------------------------------------------------------------

/// Bundles the RS-specific scratch state passed through the emit pipeline.
struct RsScratchRef<'a> {
    data_buffers: &'a mut [Vec<u8>],
    parity_buffers: &'a mut [Vec<u8>],
    encoder: &'a reed_solomon_erasure::galois_8::ReedSolomon,
}

fn buffer_rs_data_shard(
    fec_group_size: usize,
    chunk_idx: usize,
    payload_slice: &[u8],
    chunk_size: usize,
    rs_data_buffers: &mut [Vec<u8>],
) {
    let group_offset = chunk_idx % fec_group_size;
    let buf = &mut rs_data_buffers[group_offset];
    buf[..chunk_size].fill(0_u8);
    buf[..payload_slice.len()].copy_from_slice(payload_slice);
}

fn encode_and_emit_rs_parity(
    parity_context: &ParityContext,
    chunk_idx: usize,
    rs: &mut RsScratchRef<'_>,
    emit_context: &EmitContext<'_>,
    runtime: &mut EmitRuntime<'_>,
) -> Result<()> {
    let (data_shards, parity_shards) = parity_context.fec_mode.rs_params();
    let ds = usize::from(data_shards);
    let ps = usize::from(parity_shards);
    let group_offset = chunk_idx % parity_context.fec_group_size;
    let actual_data = group_offset + 1;
    let chunk_size = usize::from(parity_context.chunk_size_u16);

    // Zero-fill unused data slots in final (partial) group
    for buf in rs.data_buffers.iter_mut().take(ds).skip(actual_data) {
        buf[..chunk_size].fill(0_u8);
    }
    // Zero-fill parity buffers before encode
    for buf in rs.parity_buffers.iter_mut().take(ps) {
        buf[..chunk_size].fill(0_u8);
    }

    // RS encode using cached encoder
    let data_refs: Vec<&[u8]> = rs.data_buffers[..ds]
        .iter()
        .map(|b| &b[..chunk_size])
        .collect();
    let mut parity_refs: Vec<&mut [u8]> = rs.parity_buffers[..ps]
        .iter_mut()
        .map(|b| &mut b[..chunk_size])
        .collect();
    rs.encoder
        .encode_sep(&data_refs, &mut parity_refs)
        .map_err(|_| UniUdpError::encode(EncodeContext::Packet, "RS encoding failed"))?;

    // Emit parity packets
    let group_start = chunk_idx - group_offset;
    for (pi, parity_buf) in rs.parity_buffers.iter().enumerate().take(ps) {
        let parity_field = pack_rs_parity_field(data_shards, parity_shards, pi as u8)?;
        let mut header = build_parity_header(parity_context, group_start, parity_field);
        emit_attempts(
            emit_context,
            runtime,
            &mut header,
            &parity_buf[..chunk_size],
        )?;
    }
    Ok(())
}

fn maybe_emit_rs_parity_group(
    parity_context: &ParityContext,
    chunk_idx: usize,
    payload_slice: &[u8],
    rs: &mut RsScratchRef<'_>,
    emit_context: &EmitContext<'_>,
    runtime: &mut EmitRuntime<'_>,
) -> Result<()> {
    let chunk_size = usize::from(parity_context.chunk_size_u16);
    buffer_rs_data_shard(
        parity_context.fec_group_size,
        chunk_idx,
        payload_slice,
        chunk_size,
        rs.data_buffers,
    );

    let group_offset = chunk_idx % parity_context.fec_group_size;
    let group_complete = group_offset == (parity_context.fec_group_size - 1)
        || chunk_idx == (parity_context.total_chunks - 1);
    if !group_complete {
        return Ok(());
    }

    encode_and_emit_rs_parity(parity_context, chunk_idx, rs, emit_context, runtime)
}

#[cfg(feature = "tokio")]
async fn encode_and_emit_rs_parity_async(
    parity_context: &ParityContext,
    chunk_idx: usize,
    rs: &mut RsScratchRef<'_>,
    emit_context: &TokioEmitContext<'_>,
    runtime: &mut TokioEmitRuntime<'_>,
) -> Result<()> {
    let (data_shards, parity_shards) = parity_context.fec_mode.rs_params();
    let ds = usize::from(data_shards);
    let ps = usize::from(parity_shards);
    let group_offset = chunk_idx % parity_context.fec_group_size;
    let actual_data = group_offset + 1;
    let chunk_size = usize::from(parity_context.chunk_size_u16);

    for buf in rs.data_buffers.iter_mut().take(ds).skip(actual_data) {
        buf[..chunk_size].fill(0_u8);
    }
    for buf in rs.parity_buffers.iter_mut().take(ps) {
        buf[..chunk_size].fill(0_u8);
    }

    // RS encode using cached encoder
    let data_refs: Vec<&[u8]> = rs.data_buffers[..ds]
        .iter()
        .map(|b| &b[..chunk_size])
        .collect();
    let mut parity_refs: Vec<&mut [u8]> = rs.parity_buffers[..ps]
        .iter_mut()
        .map(|b| &mut b[..chunk_size])
        .collect();
    rs.encoder
        .encode_sep(&data_refs, &mut parity_refs)
        .map_err(|_| UniUdpError::encode(EncodeContext::Packet, "RS encoding failed"))?;

    let group_start = chunk_idx - group_offset;
    for (pi, parity_buf) in rs.parity_buffers.iter().enumerate().take(ps) {
        let parity_field = pack_rs_parity_field(data_shards, parity_shards, pi as u8)?;
        let mut header = build_parity_header(parity_context, group_start, parity_field);
        emit_attempts_async(
            emit_context,
            runtime,
            &mut header,
            &parity_buf[..chunk_size],
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "tokio")]
async fn maybe_emit_rs_parity_group_async(
    parity_context: &ParityContext,
    chunk_idx: usize,
    payload_slice: &[u8],
    rs: &mut RsScratchRef<'_>,
    emit_context: &TokioEmitContext<'_>,
    runtime: &mut TokioEmitRuntime<'_>,
) -> Result<()> {
    let chunk_size = usize::from(parity_context.chunk_size_u16);
    buffer_rs_data_shard(
        parity_context.fec_group_size,
        chunk_idx,
        payload_slice,
        chunk_size,
        rs.data_buffers,
    );

    let group_offset = chunk_idx % parity_context.fec_group_size;
    let group_complete = group_offset == (parity_context.fec_group_size - 1)
        || chunk_idx == (parity_context.total_chunks - 1);
    if !group_complete {
        return Ok(());
    }

    encode_and_emit_rs_parity_async(parity_context, chunk_idx, rs, emit_context, runtime).await
}
