use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourcePolicy {
    /// Accept the first packet from any source, then pin all follow-up packets
    /// for that message to the same socket address.
    AnyFirstSource,
    /// Require all packets to come from this exact socket address.
    Exact(SocketAddr),
    /// Accept the first packet from any source, then require follow-up packets
    /// to match the first packet's IP address (port may differ).
    SameIp,
}

impl SourcePolicy {
    pub(crate) fn allows_first(self, source: SocketAddr) -> bool {
        match self {
            SourcePolicy::AnyFirstSource | SourcePolicy::SameIp => true,
            SourcePolicy::Exact(expected) => source == expected,
        }
    }

    pub(crate) fn allows_existing(self, first_source: SocketAddr, incoming: SocketAddr) -> bool {
        match self {
            SourcePolicy::AnyFirstSource => incoming == first_source,
            SourcePolicy::Exact(expected) => incoming == expected && incoming == first_source,
            SourcePolicy::SameIp => incoming.ip() == first_source.ip(),
        }
    }

    pub(crate) fn allows_buffered(self, first_source: SocketAddr) -> bool {
        match self {
            SourcePolicy::AnyFirstSource | SourcePolicy::SameIp => true,
            SourcePolicy::Exact(expected) => expected == first_source,
        }
    }
}
