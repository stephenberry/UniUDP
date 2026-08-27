//! Compile-only check that uniudp is usable from a browser wasm build.
//!
//! wasm32-unknown-unknown has no sockets, so this exercises the socket-free
//! surface: frame encoding and parsing.
use uniudp::packet::{encode_packet, parse_packet, PacketHeader};

pub fn roundtrip(header: PacketHeader, payload: &[u8]) -> bool {
    match encode_packet(header, payload) {
        Ok(bytes) => parse_packet(&bytes).is_ok(),
        Err(_) => false,
    }
}
