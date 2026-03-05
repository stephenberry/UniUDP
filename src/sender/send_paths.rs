use std::net::UdpSocket;
use std::thread::sleep;
use std::time::Duration;

#[cfg(feature = "tokio")]
use tokio::net::UdpSocket as TokioUdpSocket;

use super::*;

impl Sender {
    /// Sends with a caller-provided UDP socket.
    ///
    /// Prefer this in repeated/high-throughput paths so the socket can be
    /// reused across calls, avoiding per-call bind overhead and ephemeral-port
    /// churn.
    ///
    /// This API is blocking. If `SendOptions::with_delay(...)` is non-zero, it
    /// uses `std::thread::sleep` between packet sends.
    ///
    /// This method only requires `&self`, so one `Sender` can be shared via
    /// `Arc<Sender>` across threads to keep a single monotonic identity/ID
    /// sequence.
    ///
    /// **Note:** the `message_id` is reserved before network I/O begins. If
    /// emission fails (e.g. socket error), the reserved ID is consumed and the
    /// next send will use the following ID. This is intentional — rolling back
    /// IDs is not possible when multiple threads share a sender. The receiver
    /// tolerates ID gaps via its freshness window.
    pub fn send_with_socket(
        &self,
        socket: &UdpSocket,
        request: SendRequest<'_>,
    ) -> std::result::Result<MessageKey, SendFailure> {
        self.send_with_socket_with_pacer(socket, request, sleep)
    }

    /// Sends with a caller-provided UDP socket and reusable scratch buffers.
    ///
    /// Prefer this in hot loops to avoid per-call packet buffer allocations.
    pub fn send_with_socket_with_scratch(
        &self,
        socket: &UdpSocket,
        request: SendRequest<'_>,
        scratch: &mut SendScratch,
    ) -> std::result::Result<MessageKey, SendFailure> {
        self.send_with_socket_with_pacer_and_scratch(socket, request, sleep, scratch)
    }

    /// Sends with a caller-provided UDP socket and custom pacing callback.
    pub fn send_with_socket_with_pacer<F>(
        &self,
        socket: &UdpSocket,
        request: SendRequest<'_>,
        pace: F,
    ) -> std::result::Result<MessageKey, SendFailure>
    where
        F: FnMut(Duration),
    {
        let mut scratch = SendScratch::default();
        self.send_with_socket_with_pacer_and_scratch(socket, request, pace, &mut scratch)
    }

    fn send_with_socket_with_pacer_and_scratch<F>(
        &self,
        socket: &UdpSocket,
        request: SendRequest<'_>,
        pace: F,
        scratch: &mut SendScratch,
    ) -> std::result::Result<MessageKey, SendFailure>
    where
        F: FnMut(Duration),
    {
        let SendRequest {
            destination,
            data,
            options,
            identity,
        } = request;
        let plan = self
            .prepare_send_plan(data, &options, &identity)
            .map_err(SendFailure::preflight)?;
        emit::emit_with_socket_and_pacer_with_scratch(
            socket,
            destination,
            data,
            identity.packet_auth(),
            plan,
            pace,
            scratch,
        )
        .map_err(SendFailure::emission_from_emit)
    }

    /// One-shot convenience API that binds a fresh ephemeral UDP socket per
    /// call.
    ///
    /// Prefer [`Sender::send_with_socket`] in loops/high-throughput paths to
    /// avoid repeated bind overhead and ephemeral port churn.
    pub fn send_oneshot(
        &self,
        request: SendRequest<'_>,
    ) -> std::result::Result<MessageKey, SendFailure> {
        let bind_addr = if request.destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(UniUdpError::from)
            .map_err(SendFailure::preflight)?;
        self.send_with_socket(&socket, request)
    }

    /// Async variant of [`Sender::send_with_socket`] for Tokio sockets.
    #[cfg(feature = "tokio")]
    pub async fn send_with_tokio_socket(
        &self,
        socket: &TokioUdpSocket,
        request: SendRequest<'_>,
    ) -> std::result::Result<MessageKey, SendFailure> {
        let mut scratch = SendScratch::default();
        self.send_with_tokio_socket_with_scratch(socket, request, &mut scratch)
            .await
    }

    /// Async variant of [`Sender::send_with_socket_with_scratch`] for Tokio
    /// sockets.
    #[cfg(feature = "tokio")]
    pub async fn send_with_tokio_socket_with_scratch(
        &self,
        socket: &TokioUdpSocket,
        request: SendRequest<'_>,
        scratch: &mut SendScratch,
    ) -> std::result::Result<MessageKey, SendFailure> {
        let SendRequest {
            destination,
            data,
            options,
            identity,
        } = request;
        let plan = self
            .prepare_send_plan(data, &options, &identity)
            .map_err(SendFailure::preflight)?;
        emit::emit_with_tokio_socket_with_scratch(
            socket,
            destination,
            data,
            identity.packet_auth(),
            plan,
            scratch,
        )
        .await
        .map_err(SendFailure::emission_from_emit)
    }

    /// Async one-shot convenience API that binds a fresh ephemeral Tokio UDP
    /// socket per call.
    ///
    /// Prefer [`Sender::send_with_tokio_socket`] in loops/high-throughput paths
    /// to avoid repeated bind overhead and ephemeral port churn.
    #[cfg(feature = "tokio")]
    pub async fn send_async_oneshot(
        &self,
        request: SendRequest<'_>,
    ) -> std::result::Result<MessageKey, SendFailure> {
        let bind_addr = if request.destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = TokioUdpSocket::bind(bind_addr)
            .await
            .map_err(UniUdpError::from)
            .map_err(SendFailure::preflight)?;
        self.send_with_tokio_socket(&socket, request).await
    }
}
