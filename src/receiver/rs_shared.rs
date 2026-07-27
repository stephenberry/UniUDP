use crate::fec::{MAX_RS_DATA_SHARDS, MAX_RS_PARITY_SHARDS};

/// Reed-Solomon codecs and decode scratch shared by every pending message on
/// one receiver.
///
/// A codec is the generator matrix for one `(data_shards, parity_shards)`
/// split. Building one is `O(data_shards^2)`, which is around 11.7 microseconds
/// at the widest split this protocol allows, and it depends only on the split,
/// so building one per message repeats that work for every message a sender
/// sends with the same parameters. Reconstruction only ever reads the matrix, so
/// one codec can serve every message that shares its split.
///
/// The workspace is the mutable half. It carries nothing between calls, so a
/// single buffer, grown to the largest split seen, serves every recovery on this
/// receiver rather than one buffer per pending message.
#[derive(Debug, Default)]
pub(super) struct RsShared {
    /// Keyed by `(data_shards, parity_shards)`. A linear scan beats a hash here:
    /// the protocol allows at most 64 x 16 splits, a receiver realistically sees
    /// one or two, and the comparison is two byte equalities.
    codecs: Vec<CachedCodec>,
    workspace: Vec<u8>,
}

#[derive(Debug)]
struct CachedCodec {
    data_shards: u8,
    parity_shards: u8,
    codec: reed_solomon_engine::Codec,
}

impl RsShared {
    /// The codec for `(data_shards, parity_shards)` and a workspace sized for
    /// it, building and caching the codec on first use.
    ///
    /// Returns `None` only if the split is one the codec rejects, which the FEC
    /// field's own validation already excludes.
    pub(super) fn codec_and_workspace(
        &mut self,
        data_shards: u8,
        parity_shards: u8,
    ) -> Option<(&reed_solomon_engine::Codec, &mut [u8])> {
        debug_assert!(data_shards <= MAX_RS_DATA_SHARDS);
        debug_assert!(parity_shards <= MAX_RS_PARITY_SHARDS);

        let found = self
            .codecs
            .iter()
            .position(|c| c.data_shards == data_shards && c.parity_shards == parity_shards);
        let index = match found {
            Some(index) => index,
            None => {
                let codec = reed_solomon_engine::Codec::new(
                    usize::from(data_shards),
                    usize::from(parity_shards),
                )
                .ok()?;
                self.codecs.push(CachedCodec {
                    data_shards,
                    parity_shards,
                    codec,
                });
                self.codecs.len() - 1
            }
        };

        // Borrow the two fields separately: the codec is shared, the workspace
        // is exclusive, and `reconstruct_data` wants both at once.
        let Self { codecs, workspace } = self;
        let codec = &codecs[index].codec;
        let needed = codec.workspace_len();
        if workspace.len() < needed {
            workspace.resize(needed, 0_u8);
        }
        Some((codec, &mut workspace[..needed]))
    }

    /// Releases the cached codecs and scratch.
    pub(super) fn clear(&mut self) {
        self.codecs.clear();
        self.codecs.shrink_to_fit();
        self.workspace.clear();
        self.workspace.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_split_is_built_once_and_reused() {
        let mut shared = RsShared::default();
        {
            let (codec, workspace) = shared.codec_and_workspace(4, 2).unwrap();
            assert_eq!(codec.data_shards(), 4);
            assert_eq!(codec.parity_shards(), 2);
            assert_eq!(workspace.len(), codec.workspace_len());
        }
        assert_eq!(shared.codecs.len(), 1);

        shared.codec_and_workspace(4, 2).unwrap();
        assert_eq!(shared.codecs.len(), 1, "the same split must not rebuild");

        shared.codec_and_workspace(8, 4).unwrap();
        assert_eq!(shared.codecs.len(), 2, "a new split gets its own codec");
    }

    #[test]
    fn the_workspace_grows_to_the_widest_split_and_never_shrinks() {
        let mut shared = RsShared::default();
        let small = {
            let (_, workspace) = shared.codec_and_workspace(4, 2).unwrap();
            workspace.len()
        };
        let large = {
            let (_, workspace) = shared.codec_and_workspace(64, 16).unwrap();
            workspace.len()
        };
        assert!(large > small);
        let capacity = shared.workspace.len();

        // Back to the narrow split: the slice handed out is sized for it, but
        // the buffer keeps the larger allocation so no split reallocates twice.
        let (_, workspace) = shared.codec_and_workspace(4, 2).unwrap();
        assert_eq!(workspace.len(), small);
        assert_eq!(shared.workspace.len(), capacity);
    }

    #[test]
    fn the_shared_codec_reconstructs_the_same_bytes_a_fresh_one_would() {
        let mut shared = RsShared::default();
        let mut shards: Vec<Vec<u8>> = (0..6)
            .map(|i| {
                if i < 4 {
                    vec![i as u8 + 1; 16]
                } else {
                    vec![0; 16]
                }
            })
            .collect();
        {
            let (codec, _) = shared.codec_and_workspace(4, 2).unwrap();
            codec.encode_all(&mut shards).unwrap();
        }
        let complete = shards.clone();

        let mut present = reed_solomon_engine::ShardMask::all_present(6);
        present.remove(1);
        shards[1].fill(0xFF);

        // Second use of the cached codec, after the workspace has been handed
        // out once already.
        let (codec, workspace) = shared.codec_and_workspace(4, 2).unwrap();
        codec
            .reconstruct_data(&mut shards, &present, workspace)
            .unwrap();
        assert_eq!(shards[1], complete[1]);
    }

    #[test]
    fn clear_releases_everything() {
        let mut shared = RsShared::default();
        shared.codec_and_workspace(8, 4).unwrap();
        shared.clear();
        assert!(shared.codecs.is_empty());
        assert!(shared.workspace.is_empty());
    }
}
