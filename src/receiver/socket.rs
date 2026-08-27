use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{Result, UniUdpError};
#[cfg(feature = "tokio")]
use tokio::net::UdpSocket as TokioUdpSocket;
#[cfg(feature = "tokio")]
use tokio::time::timeout as tokio_timeout;

/// Saves the socket's read timeout on construction and restores it on drop.
///
/// The blocking receive path drives its timeout budget through
/// `set_read_timeout`, so the caller's original setting must be put back even
/// if the receive returns early or unwinds.
pub(super) struct SocketReadTimeoutGuard<'a> {
    socket: &'a UdpSocket,
    previous: Option<Duration>,
}

impl<'a> SocketReadTimeoutGuard<'a> {
    pub(super) fn capture(socket: &'a UdpSocket) -> Result<Self> {
        Ok(Self {
            socket,
            previous: socket.read_timeout()?,
        })
    }
}

impl Drop for SocketReadTimeoutGuard<'_> {
    fn drop(&mut self) {
        let _ = self.socket.set_read_timeout(self.previous);
    }
}

/// Initial backoff applied when a nonblocking socket reports `WouldBlock`.
const NONBLOCKING_BACKOFF_START: Duration = Duration::from_micros(50);
/// Upper bound on the nonblocking backoff, capping added receive latency.
const NONBLOCKING_BACKOFF_MAX: Duration = Duration::from_millis(1);

/// Receives a single datagram, waiting at most `timeout`.
///
/// Callers must hold a [`SocketReadTimeoutGuard`] for the socket: this sets the
/// read timeout to the remaining budget on each attempt.
///
/// A nonblocking socket cannot wait, so `WouldBlock` is retried under a short
/// capped backoff rather than spinning a core.
pub(super) fn recv_from_timeout(
    socket: &UdpSocket,
    timeout: Duration,
    buffer: &mut [u8],
) -> Result<Option<(SocketAddr, usize)>> {
    if timeout.is_zero() {
        return Ok(None);
    }

    let start = Instant::now();
    let mut backoff = NONBLOCKING_BACKOFF_START;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        socket.set_read_timeout(Some(timeout - elapsed))?;

        match socket.recv_from(buffer) {
            Ok((len, source)) => return Ok(Some((source, len))),
            // A signal cut the wait short. The socket was willing to block, so
            // retry at once; the read timeout still bounds the budget.
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // A blocking socket spends the whole read timeout inside
                // `recv_from`, leaving no budget and exiting on the next
                // iteration. Budget left over means the socket is nonblocking
                // and returned instantly, so sleep rather than spin.
                let sleep_for = backoff.min(timeout.saturating_sub(start.elapsed()));
                if !sleep_for.is_zero() {
                    std::thread::sleep(sleep_for);
                    backoff = (backoff * 2).min(NONBLOCKING_BACKOFF_MAX);
                }
                continue;
            }
            Err(err) => return Err(UniUdpError::Io(err)),
        }
    }
}

#[cfg(feature = "tokio")]
pub(super) async fn recv_from_timeout_async(
    socket: &TokioUdpSocket,
    timeout: Duration,
    buffer: &mut [u8],
) -> Result<Option<(SocketAddr, usize)>> {
    if timeout.is_zero() {
        return Ok(None);
    }

    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        let remaining = timeout - elapsed;

        match tokio_timeout(remaining, socket.recv_from(buffer)).await {
            Ok(Ok((len, source))) => return Ok(Some((source, len))),
            Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Ok(Err(err)) => return Err(UniUdpError::Io(err)),
            Err(_) => return Ok(None),
        }
    }
}
