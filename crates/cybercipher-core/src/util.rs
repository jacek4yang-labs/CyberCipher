//! Small shared numeric utilities used by both the codec operations and the
//! engine's output reporting.

/// Shannon entropy of a byte sequence, in bits per byte (0.0 ..= 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Ratio of bytes that are printable ASCII (0x20..=0x7E) or common whitespace.
pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    printable as f64 / data.len() as f64
}

/// Ratio of bytes that form valid UTF-8-ish Latin text; approximate heuristic
/// used by scoring layers.
pub fn ascii_letter_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let letters = data
        .iter()
        .filter(|&&b| b.is_ascii_alphabetic() || b == b' ')
        .count();
    letters as f64 / data.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        // 256 distinct bytes -> exactly 8 bits/byte.
        let all: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&all);
        assert!((e - 8.0).abs() < 1e-9, "entropy {e}");
    }

    #[test]
    fn printable_ratio_basics() {
        assert_eq!(printable_ratio(b"abc \n"), 1.0);
        assert_eq!(printable_ratio(&[0x00, 0x41]), 0.5);
        assert_eq!(printable_ratio(b""), 0.0);
    }
}
