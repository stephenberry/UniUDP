use std::fmt;
use std::io;

use crate::types::{IncompletePayloadError, ReceiveDiagnostics};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    pub field: &'static str,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationContext {
    ReceiveOptions,
    ReceiverConfig,
    SendOptions,
    MessageMetadata,
    Fec,
    HeaderWrite,
    PacketWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeContext {
    Packet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeContext {
    Packet,
    Header,
    HeaderField(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiveRejectReason {
    Authentication,
    Replay,
    SourcePolicy,
    MessageMetadata,
    PendingBudget,
    SessionBudget,
}

#[derive(Debug)]
#[non_exhaustive]
/// Crate error type.
///
/// Intentionally not `Clone` because it carries `std::io::Error` for I/O
/// failures. Callers that need shared ownership can wrap errors in `Arc`.
pub enum UniUdpError {
    Io(io::Error),
    Validation {
        context: ValidationContext,
        message: &'static str,
        detail: Option<ErrorDetail>,
    },
    Encode {
        context: EncodeContext,
        message: &'static str,
    },
    Decode {
        context: DecodeContext,
        message: &'static str,
        detail: Option<ErrorDetail>,
    },
    AddressResolution,
    RejectedPacket {
        reason: ReceiveRejectReason,
    },
    TimeoutAfterRejectedTraffic {
        diagnostics: ReceiveDiagnostics,
    },
    TimeoutBeforeMatchingMessage {
        diagnostics: ReceiveDiagnostics,
    },
    TimeoutBeforeFirstPacket {
        diagnostics: ReceiveDiagnostics,
    },
    TimeoutAfterTraffic {
        diagnostics: ReceiveDiagnostics,
    },
    IncompletePayload(IncompletePayloadError),
}

impl fmt::Display for UniUdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UniUdpError::Io(err) => write!(f, "io error: {err}"),
            UniUdpError::Validation {
                context,
                message,
                detail,
            } => write!(f, "validation error ({context:?}): {message}")
                .and_then(|_| write_detail(f, detail.as_ref())),
            UniUdpError::Encode { context, message } => {
                write!(f, "encode error ({context:?}): {message}")
            }
            UniUdpError::Decode {
                context,
                message,
                detail,
            } => write!(f, "decode error ({context:?}): {message}")
                .and_then(|_| write_detail(f, detail.as_ref())),
            UniUdpError::AddressResolution => write!(f, "failed to resolve destination address"),
            UniUdpError::RejectedPacket { reason } => {
                write!(f, "packet rejected during receive ({reason:?})")
            }
            UniUdpError::TimeoutAfterRejectedTraffic { diagnostics } => {
                write!(f, "timeout after rejected traffic: {diagnostics}")
            }
            UniUdpError::TimeoutBeforeMatchingMessage { diagnostics } => {
                write!(f, "timeout before matching message: {diagnostics}")
            }
            UniUdpError::TimeoutBeforeFirstPacket { diagnostics } => {
                write!(f, "timeout exceeded before first packet: {diagnostics}")
            }
            UniUdpError::TimeoutAfterTraffic { diagnostics } => {
                write!(f, "timeout exceeded after receiving traffic: {diagnostics}")
            }
            UniUdpError::IncompletePayload(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for UniUdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UniUdpError::Io(err) => Some(err),
            UniUdpError::IncompletePayload(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for UniUdpError {
    fn from(value: io::Error) -> Self {
        UniUdpError::Io(value)
    }
}

impl From<IncompletePayloadError> for UniUdpError {
    fn from(value: IncompletePayloadError) -> Self {
        UniUdpError::IncompletePayload(value)
    }
}

impl UniUdpError {
    pub(crate) fn validation(context: ValidationContext, message: &'static str) -> Self {
        Self::Validation {
            context,
            message,
            detail: None,
        }
    }

    pub(crate) fn validation_detail(
        context: ValidationContext,
        message: &'static str,
        field: &'static str,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::Validation {
            context,
            message,
            detail: Some(ErrorDetail {
                field,
                expected: expected.into(),
                actual: actual.into(),
            }),
        }
    }

    pub(crate) fn encode(context: EncodeContext, message: &'static str) -> Self {
        Self::Encode { context, message }
    }

    pub(crate) fn decode(context: DecodeContext, message: &'static str) -> Self {
        Self::Decode {
            context,
            message,
            detail: None,
        }
    }

    pub(crate) fn decode_detail(
        context: DecodeContext,
        message: &'static str,
        field: &'static str,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::Decode {
            context,
            message,
            detail: Some(ErrorDetail {
                field,
                expected: expected.into(),
                actual: actual.into(),
            }),
        }
    }
}

fn write_detail(f: &mut fmt::Formatter<'_>, detail: Option<&ErrorDetail>) -> fmt::Result {
    if let Some(detail) = detail {
        write!(
            f,
            " [field={}, expected={}, actual={}]",
            detail.field, detail.expected, detail.actual
        )?;
    }
    Ok(())
}

pub type Result<T> = std::result::Result<T, UniUdpError>;
