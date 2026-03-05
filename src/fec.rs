use crate::error::{Result, UniUdpError, ValidationContext};

pub const FEC_PARITY_FLAG: u16 = 0x0001;
pub const FEC_MODE_RS_FLAG: u16 = 0x8000;
pub const MAX_RS_DATA_SHARDS: u8 = 64;
pub const MAX_RS_PARITY_SHARDS: u8 = 16;

/// Forward Error Correction mode for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecMode {
    /// No FEC.
    None,
    /// Reed-Solomon erasure coding. `data_shards` data chunks per group,
    /// `parity_shards` parity chunks per group. Can recover up to
    /// `parity_shards` missing data chunks per group.
    ReedSolomon { data_shards: u8, parity_shards: u8 },
}

impl FecMode {
    /// Returns the number of data chunks per FEC group, or 1 if FEC is disabled.
    #[must_use]
    pub fn effective_group_size(&self) -> usize {
        match self {
            Self::None => 1,
            Self::ReedSolomon { data_shards, .. } => usize::from(*data_shards),
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns `(data_shards, parity_shards)` for RS mode.
    /// Panics if called on a non-RS mode.
    pub(crate) fn rs_params(&self) -> (u8, u8) {
        match self {
            Self::ReedSolomon {
                data_shards,
                parity_shards,
            } => (*data_shards, *parity_shards),
            Self::None => panic!("rs_params called on non-RS FecMode"),
        }
    }

    /// Number of parity packets emitted per FEC group.
    #[must_use]
    pub fn parity_packets_per_group(&self) -> usize {
        match self {
            Self::None => 0,
            Self::ReedSolomon { parity_shards, .. } => usize::from(*parity_shards),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::ReedSolomon {
                data_shards,
                parity_shards,
            } => {
                if *data_shards == 0 {
                    return Err(UniUdpError::validation(
                        ValidationContext::Fec,
                        "RS data_shards must be at least 1",
                    ));
                }
                if *data_shards > MAX_RS_DATA_SHARDS {
                    return Err(UniUdpError::validation(
                        ValidationContext::Fec,
                        "RS data_shards exceeds maximum (64)",
                    ));
                }
                if *parity_shards == 0 {
                    return Err(UniUdpError::validation(
                        ValidationContext::Fec,
                        "RS parity_shards must be at least 1",
                    ));
                }
                if *parity_shards > MAX_RS_PARITY_SHARDS {
                    return Err(UniUdpError::validation(
                        ValidationContext::Fec,
                        "RS parity_shards exceeds maximum (16)",
                    ));
                }
                let total = u16::from(*data_shards) + u16::from(*parity_shards);
                if total > 255 {
                    return Err(UniUdpError::validation(
                        ValidationContext::Fec,
                        "RS data_shards + parity_shards exceeds GF(2^8) limit (255)",
                    ));
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// No-FEC fec_field encoding (bit 15 = 0)
//   fec_field = (group_size << 1) | parity_flag
//   For FecMode::None, group_size is always 1.
// ---------------------------------------------------------------------------

pub fn pack_fec_field(group_size: u16, is_parity: bool) -> Result<u16> {
    if group_size == 0 {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "fec_group_size must be positive",
        ));
    }
    let mut field = group_size << 1;
    if is_parity {
        field |= FEC_PARITY_FLAG;
    }
    Ok(field)
}

pub fn fec_is_parity(field: u16) -> bool {
    (field & FEC_PARITY_FLAG) != 0
}

/// Returns true if the fec_field indicates Reed-Solomon mode.
pub fn fec_is_rs(field: u16) -> bool {
    (field & FEC_MODE_RS_FLAG) != 0
}

/// Returns the effective FEC group size (data chunks per group).
/// For RS: data_shards. For non-RS (no FEC): the encoded group_size.
pub fn fec_group_size_from_field(field: u16) -> usize {
    if fec_is_rs(field) {
        let (data_shards, _, _) = rs_params_from_field(field);
        usize::from(data_shards)
    } else {
        usize::from(field >> 1)
    }
}

// ---------------------------------------------------------------------------
// RS fec_field encoding (bit 15 = 1)
//   Bit 0:     parity flag
//   Bits 1-6:  data_shards - 1   (6 bits, values 0-63 → shards 1-64)
//   Bits 7-10: parity_shards - 1 (4 bits, values 0-15 → shards 1-16)
//   Bits 11-14: parity_shard_index (4 bits, 0-15; valid only on parity packets)
//   Bit 15:    1 (RS mode flag)
// ---------------------------------------------------------------------------

/// Pack an RS data-shard fec_field (parity flag = 0).
pub fn pack_rs_data_field(data_shards: u8, parity_shards: u8) -> Result<u16> {
    validate_rs_params(data_shards, parity_shards)?;
    Ok(pack_rs_field_raw(data_shards, parity_shards, false, 0))
}

/// Pack an RS parity-shard fec_field for the given parity shard index.
pub fn pack_rs_parity_field(data_shards: u8, parity_shards: u8, parity_index: u8) -> Result<u16> {
    validate_rs_params(data_shards, parity_shards)?;
    if parity_index >= parity_shards {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "RS parity_shard_index out of range",
        ));
    }
    Ok(pack_rs_field_raw(
        data_shards,
        parity_shards,
        true,
        parity_index,
    ))
}

/// Decode RS parameters from an fec_field.
/// Returns `(data_shards, parity_shards, parity_shard_index)`.
/// `parity_shard_index` is meaningful only when `fec_is_parity()` is true.
pub fn rs_params_from_field(field: u16) -> (u8, u8, u8) {
    let data_shards = (((field >> 1) & 0x3f) as u8) + 1;
    let parity_shards = (((field >> 7) & 0x0f) as u8) + 1;
    let parity_shard_index = ((field >> 11) & 0x0f) as u8;
    (data_shards, parity_shards, parity_shard_index)
}

/// Pack an fec_field from a `FecMode`.
/// For parity packets, set `is_parity = true` and provide `parity_index`.
pub fn pack_fec_field_from_mode(mode: &FecMode, is_parity: bool, parity_index: u8) -> Result<u16> {
    match mode {
        FecMode::None => pack_fec_field(1, is_parity),
        FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        } => {
            if is_parity {
                pack_rs_parity_field(*data_shards, *parity_shards, parity_index)
            } else {
                pack_rs_data_field(*data_shards, *parity_shards)
            }
        }
    }
}

/// Decode an fec_field into a `FecMode`.
/// Parity flag and parity_shard_index are not captured in the returned mode.
pub fn fec_mode_from_field(field: u16) -> FecMode {
    if fec_is_rs(field) {
        let (data_shards, parity_shards, _) = rs_params_from_field(field);
        FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        }
    } else {
        // Non-RS field: only group_size=1 (no FEC) is valid.
        FecMode::None
    }
}

fn validate_rs_params(data_shards: u8, parity_shards: u8) -> Result<()> {
    if data_shards == 0 {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "RS data_shards must be at least 1",
        ));
    }
    if data_shards > MAX_RS_DATA_SHARDS {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "RS data_shards exceeds maximum (64)",
        ));
    }
    if parity_shards == 0 {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "RS parity_shards must be at least 1",
        ));
    }
    if parity_shards > MAX_RS_PARITY_SHARDS {
        return Err(UniUdpError::validation(
            ValidationContext::Fec,
            "RS parity_shards exceeds maximum (16)",
        ));
    }
    Ok(())
}

fn pack_rs_field_raw(data_shards: u8, parity_shards: u8, is_parity: bool, parity_index: u8) -> u16 {
    let mut field: u16 = FEC_MODE_RS_FLAG;
    if is_parity {
        field |= FEC_PARITY_FLAG;
    }
    field |= (u16::from(data_shards - 1) & 0x3f) << 1;
    field |= (u16::from(parity_shards - 1) & 0x0f) << 7;
    field |= (u16::from(parity_index) & 0x0f) << 11;
    field
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs_field_roundtrip() {
        for ds in [1_u8, 2, 16, 64] {
            for ps in [1_u8, 2, 4, 16] {
                let data_field = pack_rs_data_field(ds, ps).unwrap();
                assert!(!fec_is_parity(data_field));
                assert!(fec_is_rs(data_field));
                let (d, p, idx) = rs_params_from_field(data_field);
                assert_eq!(d, ds);
                assert_eq!(p, ps);
                assert_eq!(idx, 0);
                assert_eq!(fec_group_size_from_field(data_field), usize::from(ds));

                let mode = fec_mode_from_field(data_field);
                assert_eq!(
                    mode,
                    FecMode::ReedSolomon {
                        data_shards: ds,
                        parity_shards: ps
                    }
                );

                for pi in 0..ps {
                    let parity_field = pack_rs_parity_field(ds, ps, pi).unwrap();
                    assert!(fec_is_parity(parity_field));
                    assert!(fec_is_rs(parity_field));
                    let (d2, p2, idx2) = rs_params_from_field(parity_field);
                    assert_eq!(d2, ds);
                    assert_eq!(p2, ps);
                    assert_eq!(idx2, pi);
                }
            }
        }
    }

    #[test]
    fn rs_parity_index_out_of_range() {
        assert!(pack_rs_parity_field(4, 2, 2).is_err());
        assert!(pack_rs_parity_field(4, 2, 1).is_ok());
    }

    #[test]
    fn rs_zero_shards_rejected() {
        assert!(pack_rs_data_field(0, 2).is_err());
        assert!(pack_rs_data_field(2, 0).is_err());
    }

    #[test]
    fn rs_max_shards() {
        assert!(pack_rs_data_field(MAX_RS_DATA_SHARDS, MAX_RS_PARITY_SHARDS).is_ok());
        assert!(pack_rs_data_field(MAX_RS_DATA_SHARDS + 1, 1).is_err());
        assert!(pack_rs_data_field(1, MAX_RS_PARITY_SHARDS + 1).is_err());
    }

    #[test]
    fn fec_mode_validate() {
        assert!(FecMode::None.validate().is_ok());
        assert!(FecMode::ReedSolomon {
            data_shards: 16,
            parity_shards: 4
        }
        .validate()
        .is_ok());
        assert!(FecMode::ReedSolomon {
            data_shards: 0,
            parity_shards: 4
        }
        .validate()
        .is_err());
        assert!(FecMode::ReedSolomon {
            data_shards: 16,
            parity_shards: 0
        }
        .validate()
        .is_err());
        assert!(FecMode::ReedSolomon {
            data_shards: 65,
            parity_shards: 1
        }
        .validate()
        .is_err());
        assert!(FecMode::ReedSolomon {
            data_shards: 1,
            parity_shards: 17
        }
        .validate()
        .is_err());
    }

    #[test]
    fn pack_from_mode_roundtrip() {
        let modes = [
            FecMode::None,
            FecMode::ReedSolomon {
                data_shards: 8,
                parity_shards: 3,
            },
        ];
        for mode in &modes {
            let data_field = pack_fec_field_from_mode(mode, false, 0).unwrap();
            assert!(!fec_is_parity(data_field));
            let decoded = fec_mode_from_field(data_field);
            assert_eq!(decoded, *mode);
        }
    }

    #[test]
    fn no_fec_field_roundtrip() {
        let field = pack_fec_field(1, false).unwrap();
        assert!(!fec_is_parity(field));
        assert!(!fec_is_rs(field));
        assert_eq!(fec_mode_from_field(field), FecMode::None);
    }
}
