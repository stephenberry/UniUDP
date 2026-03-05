use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[cfg(unix)]
use mio::unix::SourceFd;
#[cfg(windows)]
use mio::windows::SourceSocket;
use mio::{Events, Interest, Poll, Token};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use crate::error::{Result, UniUdpError};
#[cfg(feature = "tokio")]
use tokio::net::UdpSocket as TokioUdpSocket;
#[cfg(feature = "tokio")]
use tokio::time::timeout as tokio_timeout;

const SOCKET_TOKEN: Token = Token(0);

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

#[cfg(any(unix, windows))]
pub(super) struct SocketReadinessWaiter {
    poll: Poll,
    events: Events,
    #[cfg(unix)]
    raw_fd: RawFd,
    #[cfg(windows)]
    raw_socket: RawSocket,
}

#[cfg(not(any(unix, windows)))]
pub(super) struct SocketReadinessWaiter;

#[cfg(unix)]
impl SocketReadinessWaiter {
    pub(super) fn new(socket: &UdpSocket) -> Result<Self> {
        let poll = Poll::new()?;
        let raw_fd = socket.as_raw_fd();
        let mut source = SourceFd(&raw_fd);
        poll.registry()
            .register(&mut source, SOCKET_TOKEN, Interest::READABLE)?;
        Ok(Self {
            poll,
            events: Events::with_capacity(4),
            raw_fd,
        })
    }

    fn wait_until_readable(&mut self, timeout: Duration) -> io::Result<bool> {
        let mut source = SourceFd(&self.raw_fd);
        self.poll
            .registry()
            .reregister(&mut source, SOCKET_TOKEN, Interest::READABLE)?;
        poll_until_readable(&mut self.poll, &mut self.events, timeout)
    }
}

#[cfg(unix)]
impl Drop for SocketReadinessWaiter {
    fn drop(&mut self) {
        let mut source = SourceFd(&self.raw_fd);
        let _ = self.poll.registry().deregister(&mut source);
    }
}

#[cfg(windows)]
impl SocketReadinessWaiter {
    pub(super) fn new(socket: &UdpSocket) -> Result<Self> {
        let poll = Poll::new()?;
        let raw_socket = socket.as_raw_socket();
        let mut source = SourceSocket(&raw_socket);
        poll.registry()
            .register(&mut source, SOCKET_TOKEN, Interest::READABLE)?;
        Ok(Self {
            poll,
            events: Events::with_capacity(4),
            raw_socket,
        })
    }

    fn wait_until_readable(&mut self, timeout: Duration) -> io::Result<bool> {
        let mut source = SourceSocket(&self.raw_socket);
        self.poll
            .registry()
            .reregister(&mut source, SOCKET_TOKEN, Interest::READABLE)?;
        poll_until_readable(&mut self.poll, &mut self.events, timeout)
    }
}

#[cfg(windows)]
impl Drop for SocketReadinessWaiter {
    fn drop(&mut self) {
        let mut source = SourceSocket(&self.raw_socket);
        let _ = self.poll.registry().deregister(&mut source);
    }
}

#[cfg(not(any(unix, windows)))]
impl SocketReadinessWaiter {
    pub(super) fn new(_socket: &UdpSocket) -> Result<Self> {
        Ok(Self)
    }
}

#[cfg(any(unix, windows))]
pub(super) fn recv_from_timeout(
    socket: &UdpSocket,
    timeout: Duration,
    buffer: &mut [u8],
    readiness: &mut SocketReadinessWaiter,
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
        if !readiness.wait_until_readable(remaining)? {
            return Ok(None);
        }

        match socket.recv_from(buffer) {
            Ok((len, source)) => return Ok(Some((source, len))),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(err) => return Err(UniUdpError::Io(err)),
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn recv_from_timeout(
    socket: &UdpSocket,
    timeout: Duration,
    buffer: &mut [u8],
    _readiness: &mut SocketReadinessWaiter,
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
        socket.set_read_timeout(Some(remaining))?;

        match socket.recv_from(buffer) {
            Ok((len, source)) => return Ok(Some((source, len))),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
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

fn poll_until_readable(
    poll: &mut Poll,
    events: &mut Events,
    timeout: Duration,
) -> io::Result<bool> {
    if timeout.is_zero() {
        return Ok(false);
    }

    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Ok(false);
        }
        let remaining = timeout - elapsed;

        events.clear();
        match poll.poll(events, Some(remaining)) {
            Ok(()) => {
                if events.is_empty() {
                    return Ok(false);
                }
                if events
                    .iter()
                    .any(|event| event.token() == SOCKET_TOKEN && event.is_readable())
                {
                    return Ok(true);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}
