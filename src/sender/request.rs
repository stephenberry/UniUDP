use std::net::SocketAddr;

use crate::types::{SendIdentityOverrides, SendOptions};

/// Request object for sending a message.
///
/// This combines destination, payload, transport options, and optional per-
/// message identity/auth overrides into one value to avoid combinatorial send
/// method signatures.
#[derive(Debug, Clone)]
pub struct SendRequest<'a> {
    pub(super) destination: SocketAddr,
    pub(super) data: &'a [u8],
    pub(super) options: SendOptions,
    pub(super) identity: SendIdentityOverrides,
}

impl<'a> SendRequest<'a> {
    #[must_use]
    pub fn new(destination: SocketAddr, data: &'a [u8]) -> Self {
        Self {
            destination,
            data,
            options: SendOptions::new(),
            identity: SendIdentityOverrides::new(),
        }
    }

    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    #[must_use]
    pub fn options(&self) -> &SendOptions {
        &self.options
    }

    #[must_use]
    pub fn identity(&self) -> &SendIdentityOverrides {
        &self.identity
    }

    #[must_use]
    pub fn with_destination(mut self, destination: SocketAddr) -> Self {
        self.destination = destination;
        self
    }

    #[must_use]
    pub fn with_data<'b>(self, data: &'b [u8]) -> SendRequest<'b> {
        SendRequest {
            destination: self.destination,
            data,
            options: self.options,
            identity: self.identity,
        }
    }

    #[must_use]
    pub fn with_options(mut self, options: SendOptions) -> Self {
        self.options = options;
        self
    }

    #[must_use]
    pub fn with_identity(mut self, identity: SendIdentityOverrides) -> Self {
        self.identity = identity;
        self
    }
}
