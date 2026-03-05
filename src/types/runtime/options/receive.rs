use std::time::Duration;

use crate::error::{UniUdpError, ValidationContext};
use crate::types::{MessageKey, SourcePolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Runtime receive behavior controls.
///
/// Defaults are tuned for local/LAN use with moderate jitter tolerance:
/// inactivity timeout `500ms`, overall timeout `5s`.
pub struct ReceiveOptions {
    key: Option<MessageKey>,
    source_policy: SourcePolicy,
    strict_rejections: bool,
    inactivity_timeout: Duration,
    overall_timeout: Duration,
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        Self {
            key: None,
            source_policy: SourcePolicy::AnyFirstSource,
            strict_rejections: false,
            // Balanced default for local/LAN use without being so short that
            // modest jitter causes frequent spurious inactivity timeouts.
            inactivity_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_secs(5),
        }
    }
}

impl ReceiveOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn key(&self) -> Option<MessageKey> {
        self.key
    }

    #[must_use]
    pub fn source_policy(&self) -> SourcePolicy {
        self.source_policy
    }

    #[must_use]
    pub fn strict_rejections(&self) -> bool {
        self.strict_rejections
    }

    #[must_use]
    pub fn inactivity_timeout(&self) -> Duration {
        self.inactivity_timeout
    }

    #[must_use]
    pub fn overall_timeout(&self) -> Duration {
        self.overall_timeout
    }

    #[must_use]
    pub fn with_key(mut self, key: MessageKey) -> Self {
        self.key = Some(key);
        self
    }

    #[must_use]
    pub fn with_key_opt(mut self, key: Option<MessageKey>) -> Self {
        self.key = key;
        self
    }

    #[must_use]
    pub fn with_source_policy(mut self, source_policy: SourcePolicy) -> Self {
        self.source_policy = source_policy;
        self
    }

    #[must_use]
    pub fn with_strict_rejections(mut self, strict_rejections: bool) -> Self {
        self.strict_rejections = strict_rejections;
        self
    }

    #[must_use]
    pub fn with_inactivity_timeout(mut self, inactivity_timeout: Duration) -> Self {
        self.inactivity_timeout = inactivity_timeout;
        self
    }

    #[must_use]
    pub fn with_overall_timeout(mut self, overall_timeout: Duration) -> Self {
        self.overall_timeout = overall_timeout;
        self
    }

    pub fn validate(&self) -> std::result::Result<(), UniUdpError> {
        if self.overall_timeout.is_zero() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiveOptions,
                "overall_timeout must be positive",
                "overall_timeout",
                "> 0s",
                format!("{:?}", self.overall_timeout),
            ));
        }
        if self.inactivity_timeout.is_zero() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiveOptions,
                "inactivity_timeout must be positive",
                "inactivity_timeout",
                "> 0s",
                format!("{:?}", self.inactivity_timeout),
            ));
        }
        Ok(())
    }
}
