use std::time::Duration;

use crate::error::{UniUdpError, ValidationContext};
use crate::fec::FecMode;

use super::super::constants::{DEFAULT_CHUNK_SIZE, HEADER_LENGTH, MAX_UDP_PAYLOAD_HARD_LIMIT};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Per-message transport settings.
///
/// This struct intentionally excludes sender/session/message identity so
/// transport tuning is independent from identity overrides.
pub struct SendOptions {
    redundancy: u16,
    chunk_size: u16,
    fec_mode: FecMode,
    delay: Duration,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            redundancy: 1,
            chunk_size: DEFAULT_CHUNK_SIZE as u16,
            fec_mode: FecMode::None,
            delay: Duration::from_millis(0),
        }
    }
}

impl SendOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn redundancy(&self) -> u16 {
        self.redundancy
    }

    #[must_use]
    pub fn chunk_size(&self) -> u16 {
        self.chunk_size
    }

    #[must_use]
    pub fn fec_mode(&self) -> &FecMode {
        &self.fec_mode
    }

    #[must_use]
    pub fn delay(&self) -> Duration {
        self.delay
    }

    #[must_use]
    pub fn with_redundancy(mut self, redundancy: u16) -> Self {
        self.redundancy = redundancy;
        self
    }

    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: u16) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    #[must_use]
    pub fn with_fec_mode(mut self, fec_mode: FecMode) -> Self {
        self.fec_mode = fec_mode;
        self
    }

    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn validate(&self) -> std::result::Result<(), UniUdpError> {
        if self.redundancy == 0 {
            return Err(UniUdpError::validation(
                ValidationContext::SendOptions,
                "redundancy must be at least 1",
            ));
        }
        if self.chunk_size == 0 {
            return Err(UniUdpError::validation(
                ValidationContext::SendOptions,
                "chunk_size must be positive",
            ));
        }
        if usize::from(self.chunk_size).saturating_add(HEADER_LENGTH) > MAX_UDP_PAYLOAD_HARD_LIMIT {
            return Err(UniUdpError::validation(
                ValidationContext::SendOptions,
                "chunk_size exceeds UDP datagram payload limit",
            ));
        }
        self.fec_mode.validate()?;
        Ok(())
    }
}
