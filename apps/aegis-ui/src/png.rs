//! Minimal PNG (RGBA8) writer for `--screenshot`, so UI checks need no
//! image-codec dependency.
use std::io::Write;

fn crc32(chunks: &[&[u8]]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for data in chunks {
        for &b in *data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    0xEDB8_8320 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
    }
    !crc
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
}

/// Encode `rgba` (row-major, 4 bytes per pixel) as PNG.
pub fn encode(width: u32, height: u32, rgba: &[u8]) -> std::io::Result<Vec<u8>> {
    let row = width as usize * 4;
    if rgba.len() != row * height as usize {
        return Err(std::io::Error::other("pixel buffer size mismatch"));
    }
    let mut raw = Vec::with_capacity((row + 1) * height as usize);
    for line in rgba.chunks(row) {
        raw.push(0); // filter: none
        raw.extend_from_slice(line);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&raw)?;
    let idat = z.finish()?;
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_png_reference_value() {
        // CRC of the IEND chunk type is fixed by the PNG specification.
        assert_eq!(crc32(&[b"IEND"]), 0xAE42_6082);
    }

    #[test]
    fn encodes_a_valid_header_and_rejects_bad_sizes() {
        let png = encode(2, 1, &[255, 0, 0, 255, 0, 255, 0, 255]).unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(png.ends_with(&[0xAE, 0x42, 0x60, 0x82]));
        assert!(encode(2, 2, &[0; 4]).is_err());
    }
}
