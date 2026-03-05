use std::time::Instant;

use crate::error::ValidationContext;

#[cfg(feature = "tokio")]
use super::socket::recv_from_timeout_async;
use super::socket::{recv_from_timeout, SocketReadTimeoutGuard, SocketReadinessWaiter};
use super::{
    CompletionReason, MessageReport, ReceiveDiagnostics, ReceiveLoopControl, ReceiveLoopDecision,
};
use super::{ReceiveOptions, ReceivePacketOutcome, Receiver, Result, UniUdpError};

impl Receiver {
    fn validate_receive_loop_options(options: &ReceiveOptions) -> Result<()> {
        options.validate()?;
        if options.key().is_some() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiveOptions,
                "receive_loop does not support keyed ReceiveOptions; use receive_message for keyed receive",
                "key",
                "None",
                format!("{:?}", options.key()),
            ));
        }
        Ok(())
    }

    fn handle_timeout(
        &mut self,
        options: &ReceiveOptions,
        diagnostics: ReceiveDiagnostics,
        saw_traffic: bool,
        reason: CompletionReason,
    ) -> Result<MessageReport> {
        if let Some(filter_key) = options.key() {
            if let Some(partial) = self
                .state
                .remove_pending_if_allowed(filter_key, options.source_policy())
            {
                let report = partial.build_report(reason);
                return self.finish_with_report(diagnostics, report);
            }
        }

        if diagnostics.packets_accepted == 0 && diagnostics.has_rejected_traffic() {
            return self.finish_with_error(
                diagnostics,
                UniUdpError::TimeoutAfterRejectedTraffic { diagnostics },
            );
        }

        if options.key().is_some() && saw_traffic {
            return self.finish_with_error(
                diagnostics,
                UniUdpError::TimeoutBeforeMatchingMessage { diagnostics },
            );
        }

        if saw_traffic {
            return self.finish_with_error(
                diagnostics,
                UniUdpError::TimeoutAfterTraffic { diagnostics },
            );
        }

        self.finish_with_error(
            diagnostics,
            UniUdpError::TimeoutBeforeFirstPacket { diagnostics },
        )
    }

    fn next_receive_decision(
        &mut self,
        options: &ReceiveOptions,
        start: Instant,
    ) -> ReceiveLoopDecision {
        loop {
            let now = Instant::now();
            self.state.cleanup(now, &self.config);
            if let Some(complete) = self
                .state
                .find_complete_message(options.key(), options.source_policy())
            {
                if self.state.is_duplicate(complete.key) {
                    continue;
                }
                self.state.mark_completed(complete.key, now, &self.config);
                let report = complete.build_report(CompletionReason::Completed);
                return ReceiveLoopDecision::ReturnReport(report);
            }

            let elapsed = start.elapsed();
            if elapsed >= options.overall_timeout() {
                return ReceiveLoopDecision::Timeout(CompletionReason::OverallTimeout);
            }

            let remaining = options.overall_timeout() - elapsed;
            let wait_time = options.inactivity_timeout().min(remaining);
            return ReceiveLoopDecision::AwaitPacket {
                cleanup_at: now,
                wait_time,
            };
        }
    }

    fn process_received_packet(
        &mut self,
        next_packet: Option<(std::net::SocketAddr, usize)>,
        cleanup_at: Instant,
        options: &ReceiveOptions,
        diagnostics: &mut ReceiveDiagnostics,
        saw_traffic: &mut bool,
    ) -> Result<ReceivePacketOutcome> {
        let Some((source, packet_len)) = next_packet else {
            return Ok(ReceivePacketOutcome::InactivityTimeout);
        };
        *saw_traffic = true;
        diagnostics.packets_received = diagnostics.packets_received.saturating_add(1);

        let Some(report) =
            self.handle_packet(packet_len, source, cleanup_at, options, diagnostics)?
        else {
            return Ok(ReceivePacketOutcome::Continue);
        };
        Ok(ReceivePacketOutcome::Complete(Box::new(report)))
    }

    fn receive_single_sync(
        &mut self,
        socket: &std::net::UdpSocket,
        readiness: &mut SocketReadinessWaiter,
        options: &ReceiveOptions,
    ) -> Result<MessageReport> {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();

        let start = Instant::now();
        let mut diagnostics = ReceiveDiagnostics::default();
        let mut saw_traffic = false;
        let reason = loop {
            let (cleanup_at, wait_time) = match self.next_receive_decision(options, start) {
                ReceiveLoopDecision::ReturnReport(report) => {
                    return self.finish_with_report(diagnostics, report);
                }
                ReceiveLoopDecision::Timeout(reason) => break reason,
                ReceiveLoopDecision::AwaitPacket {
                    cleanup_at,
                    wait_time,
                } => (cleanup_at, wait_time),
            };

            let next_packet =
                recv_from_timeout(socket, wait_time, &mut self.recv_buffer, readiness)?;
            match self.process_received_packet(
                next_packet,
                cleanup_at,
                options,
                &mut diagnostics,
                &mut saw_traffic,
            )? {
                ReceivePacketOutcome::Continue => {}
                ReceivePacketOutcome::Complete(report) => {
                    return self.finish_with_report(diagnostics, *report);
                }
                ReceivePacketOutcome::InactivityTimeout => {
                    break CompletionReason::InactivityTimeout;
                }
            }
        };

        self.handle_timeout(options, diagnostics, saw_traffic, reason)
    }

    #[cfg(feature = "tokio")]
    async fn receive_single_async(
        &mut self,
        socket: &tokio::net::UdpSocket,
        options: &ReceiveOptions,
    ) -> Result<MessageReport> {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();

        let start = Instant::now();
        let mut diagnostics = ReceiveDiagnostics::default();
        let mut saw_traffic = false;
        let reason = loop {
            let (cleanup_at, wait_time) = match self.next_receive_decision(options, start) {
                ReceiveLoopDecision::ReturnReport(report) => {
                    return self.finish_with_report(diagnostics, report);
                }
                ReceiveLoopDecision::Timeout(reason) => break reason,
                ReceiveLoopDecision::AwaitPacket {
                    cleanup_at,
                    wait_time,
                } => (cleanup_at, wait_time),
            };

            let next_packet =
                recv_from_timeout_async(socket, wait_time, &mut self.recv_buffer).await?;
            match self.process_received_packet(
                next_packet,
                cleanup_at,
                options,
                &mut diagnostics,
                &mut saw_traffic,
            )? {
                ReceivePacketOutcome::Continue => {}
                ReceivePacketOutcome::Complete(report) => {
                    return self.finish_with_report(diagnostics, *report);
                }
                ReceivePacketOutcome::InactivityTimeout => {
                    break CompletionReason::InactivityTimeout;
                }
            }
        };

        self.handle_timeout(options, diagnostics, saw_traffic, reason)
    }

    /// Receives one message from `socket`.
    ///
    /// Takes `&mut UdpSocket` because the implementation temporarily changes
    /// the socket's read timeout and restores it on return. The `&mut`
    /// prevents concurrent access that could interfere with the
    /// save/restore cycle. (The async variant uses `tokio::time::timeout`
    /// instead, so it only needs `&`.)
    ///
    /// Blocking sockets are preferred. Nonblocking sockets are also supported:
    /// `WouldBlock` is treated as no-data-yet and waits on socket readiness
    /// until timeout budget is exhausted.
    /// Do not concurrently receive from the same `UdpSocket` (including any
    /// `try_clone()` handles) while this method is running.
    pub fn receive_message(
        &mut self,
        socket: &mut std::net::UdpSocket,
        options: ReceiveOptions,
    ) -> Result<MessageReport> {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();
        options.validate()?;
        self.ensure_recv_buffer();

        let _timeout_guard = SocketReadTimeoutGuard::capture(socket)?;
        let mut readiness = SocketReadinessWaiter::new(socket)?;
        self.receive_single_sync(socket, &mut readiness, &options)
    }

    /// Repeatedly receives messages from `socket` and invokes `on_message` for
    /// each completed report.
    ///
    /// Takes `&mut UdpSocket` for the same reason as [`Receiver::receive_message`]:
    /// the read timeout is temporarily modified during the call.
    ///
    /// Per-message timeout budgets come from `options` on each iteration.
    /// Keyed filtering (`ReceiveOptions::with_key`) is not supported here;
    /// use [`Receiver::receive_message`] for keyed single-message receives.
    /// The loop stops when `on_message` returns [`ReceiveLoopControl::Stop`] or
    /// when a receive error occurs.
    /// Do not concurrently receive from the same `UdpSocket` (including any
    /// `try_clone()` handles) while this method is running.
    pub fn receive_loop<F>(
        &mut self,
        socket: &mut std::net::UdpSocket,
        options: ReceiveOptions,
        mut on_message: F,
    ) -> Result<usize>
    where
        F: FnMut(MessageReport) -> ReceiveLoopControl,
    {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();
        Self::validate_receive_loop_options(&options)?;
        self.ensure_recv_buffer();

        let _timeout_guard = SocketReadTimeoutGuard::capture(socket)?;
        let mut readiness = SocketReadinessWaiter::new(socket)?;
        let mut delivered = 0usize;
        loop {
            let report = self.receive_single_sync(socket, &mut readiness, &options)?;
            delivered = delivered.saturating_add(1);
            if matches!(on_message(report), ReceiveLoopControl::Stop) {
                return Ok(delivered);
            }
        }
    }

    /// Async variant of [`Receiver::receive_message`] for Tokio sockets.
    ///
    /// This call requires exclusive ownership of the socket for the full
    /// receive duration.
    ///
    /// Do not concurrently receive from the same `tokio::net::UdpSocket`
    /// (including any `try_clone()` handles) while this method is running.
    #[cfg(feature = "tokio")]
    pub async fn receive_message_async(
        &mut self,
        socket: &tokio::net::UdpSocket,
        options: ReceiveOptions,
    ) -> Result<MessageReport> {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();
        options.validate()?;
        self.ensure_recv_buffer();
        self.receive_single_async(socket, &options).await
    }

    /// Async variant of [`Receiver::receive_loop`] for Tokio sockets.
    ///
    /// Per-message timeout budgets come from `options` on each iteration.
    /// Keyed filtering (`ReceiveOptions::with_key`) is not supported here;
    /// use [`Receiver::receive_message_async`] for keyed single-message
    /// receives.
    /// The loop stops when `on_message(...).await` returns
    /// [`ReceiveLoopControl::Stop`] or when a receive error occurs.
    #[cfg(feature = "tokio")]
    pub async fn receive_loop_async<F, Fut>(
        &mut self,
        socket: &tokio::net::UdpSocket,
        options: ReceiveOptions,
        mut on_message: F,
    ) -> Result<usize>
    where
        F: FnMut(MessageReport) -> Fut,
        Fut: std::future::Future<Output = ReceiveLoopControl>,
    {
        self.last_receive_diagnostics = ReceiveDiagnostics::default();
        Self::validate_receive_loop_options(&options)?;
        self.ensure_recv_buffer();

        let mut delivered = 0usize;
        loop {
            let report = self.receive_single_async(socket, &options).await?;
            delivered = delivered.saturating_add(1);
            if matches!(on_message(report).await, ReceiveLoopControl::Stop) {
                return Ok(delivered);
            }
        }
    }
}
