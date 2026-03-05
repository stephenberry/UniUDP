#[must_use]
pub fn packet_crc32c(header_without_checksum: &[u8], payload: &[u8]) -> u32 {
    let crc = crc32c::crc32c_append(0, header_without_checksum);
    crc32c::crc32c_append(crc, payload)
}
