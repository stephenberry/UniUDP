#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompletionReason {
    Completed,
    InactivityTimeout,
    OverallTimeout,
}
