use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use crate::types::MessageKey;

#[derive(Debug, Default)]
pub(super) struct TimestampKeyIndex {
    order: BTreeMap<(Instant, u64), MessageKey>,
    order_key: HashMap<MessageKey, (Instant, u64)>,
    next_seq: u64,
}

impl TimestampKeyIndex {
    pub(super) fn clear(&mut self) {
        self.order.clear();
        self.order_key.clear();
        self.next_seq = 0;
    }

    pub(super) fn insert(&mut self, key: MessageKey, timestamp: Instant) {
        self.remove(&key);
        let order_key = self.alloc_order_key(timestamp);
        self.order.insert(order_key, key);
        self.order_key.insert(key, order_key);
        self.debug_assert_invariants();
    }

    pub(super) fn remove(&mut self, key: &MessageKey) -> bool {
        let removed = self.order_key.remove(key);
        if let Some(order_key) = removed {
            self.order.remove(&order_key);
        }
        self.debug_assert_invariants();
        removed.is_some()
    }

    pub(super) fn oldest(&self) -> Option<(Instant, MessageKey)> {
        self.order
            .first_key_value()
            .map(|(&(timestamp, _), &key)| (timestamp, key))
    }

    pub(super) fn contains_key(&self, key: &MessageKey) -> bool {
        self.order_key.contains_key(key)
    }

    pub(super) fn len(&self) -> usize {
        self.order_key.len()
    }

    fn alloc_order_key(&mut self, timestamp: Instant) -> (Instant, u64) {
        let mut seq = self.next_seq;
        while self.order.contains_key(&(timestamp, seq)) {
            seq = seq.wrapping_add(1);
        }
        self.next_seq = seq.wrapping_add(1);
        (timestamp, seq)
    }

    #[cfg(debug_assertions)]
    pub(super) fn debug_assert_invariants(&self) {
        debug_assert_eq!(self.order.len(), self.order_key.len());
        for (order_key, key) in &self.order {
            debug_assert_eq!(self.order_key.get(key), Some(order_key));
        }
        for (key, order_key) in &self.order_key {
            debug_assert_eq!(self.order.get(order_key), Some(key));
        }
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn debug_assert_invariants(&self) {}
}

#[derive(Debug, Default)]
pub(super) struct SequenceKeyIndex {
    order: BTreeMap<u64, MessageKey>,
    order_key: HashMap<MessageKey, u64>,
    next_seq: u64,
}

impl SequenceKeyIndex {
    pub(super) fn clear(&mut self) {
        self.order.clear();
        self.order_key.clear();
        self.next_seq = 0;
    }

    pub(super) fn insert_if_absent(&mut self, key: MessageKey) -> bool {
        if self.order_key.contains_key(&key) {
            return false;
        }
        let seq = self.alloc_seq();
        self.order.insert(seq, key);
        self.order_key.insert(key, seq);
        self.debug_assert_invariants();
        true
    }

    pub(super) fn remove(&mut self, key: &MessageKey) -> bool {
        let removed = self.order_key.remove(key);
        if let Some(seq) = removed {
            self.order.remove(&seq);
        }
        self.debug_assert_invariants();
        removed.is_some()
    }

    pub(super) fn remove_exact(&mut self, seq: u64, key: MessageKey) {
        if self.order.get(&seq).copied() == Some(key) {
            self.order.remove(&seq);
            self.order_key.remove(&key);
        }
        self.debug_assert_invariants();
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = (u64, MessageKey)> + '_ {
        self.order.iter().map(|(&seq, &key)| (seq, key))
    }

    pub(super) fn len(&self) -> usize {
        self.order_key.len()
    }

    fn alloc_seq(&mut self) -> u64 {
        let mut seq = self.next_seq;
        while self.order.contains_key(&seq) {
            seq = seq.wrapping_add(1);
        }
        self.next_seq = seq.wrapping_add(1);
        seq
    }

    #[cfg(debug_assertions)]
    pub(super) fn debug_assert_invariants(&self) {
        debug_assert_eq!(self.order.len(), self.order_key.len());
        for (seq, key) in &self.order {
            debug_assert_eq!(self.order_key.get(key), Some(seq));
        }
        for (key, seq) in &self.order_key {
            debug_assert_eq!(self.order.get(seq), Some(key));
        }
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn debug_assert_invariants(&self) {}
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::types::{MessageKey, SenderId};

    use super::{SequenceKeyIndex, TimestampKeyIndex};

    fn key(sender: u128, message: u64) -> MessageKey {
        MessageKey {
            sender_id: SenderId(sender),
            session_nonce: 0,
            message_id: message,
        }
    }

    #[test]
    fn timestamp_key_index_replaces_existing_key_without_leaking_order_entries() {
        let mut index = TimestampKeyIndex::default();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(5);
        let k1 = key(1, 10);
        let k2 = key(2, 20);

        index.insert(k1, t0);
        index.insert(k2, t0);
        assert_eq!(index.len(), 2);

        index.insert(k1, t1);
        assert_eq!(index.len(), 2);
        assert_eq!(index.oldest(), Some((t0, k2)));

        assert!(index.remove(&k2));
        assert_eq!(index.len(), 1);
        assert_eq!(index.oldest(), Some((t1, k1)));
        assert!(!index.remove(&k2));
    }

    #[test]
    fn sequence_key_index_remove_exact_only_removes_matching_pair() {
        let mut index = SequenceKeyIndex::default();
        let k1 = key(3, 30);
        let k2 = key(4, 40);

        assert!(index.insert_if_absent(k1));
        assert!(index.insert_if_absent(k2));
        assert!(!index.insert_if_absent(k2));

        let entries: Vec<(u64, MessageKey)> = index.entries().collect();
        let (seq_k1, key_k1) = entries[0];
        let (seq_k2, key_k2) = entries[1];
        assert_eq!(key_k1, k1);
        assert_eq!(key_k2, k2);

        index.remove_exact(seq_k2, k1);
        assert_eq!(index.len(), 2);

        index.remove_exact(seq_k1, k1);
        assert_eq!(index.len(), 1);
        assert_eq!(index.entries().next(), Some((seq_k2, k2)));
    }
}
