use anyhow::Result;
use object::{Object, ObjectSection};
use serde::Serialize;

/// Shannon entropy result for a single binary section.
#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    /// Section name (e.g. `.text`, `.data`, `UPX0`)
    pub name: String,
    /// Computed entropy in [0.0, 8.0]
    pub entropy: f64,
    /// Raw byte size of the section
    pub size: u64,
}

impl SectionEntropy {
    /// Analyze all sections of the binary and return their entropy values.
    pub fn analyze(data: &[u8]) -> Result<Vec<SectionEntropy>> {
        let obj = object::File::parse(data)?;
        let mut results = Vec::new();

        for section in obj.sections() {
            let name = section.name().unwrap_or("<unnamed>").to_owned();
            let section_data = match section.data() {
                Ok(d) if !d.is_empty() => d,
                _ => continue,
            };
            let entropy = calculate_entropy(section_data);
            let size = section_data.len() as u64;
            results.push(SectionEntropy {
                name,
                entropy,
                size,
            });
        }

        // If the object format exposes no sections (some PE/raw blobs),
        // fall back to whole-file entropy.
        if results.is_empty() {
            results.push(SectionEntropy {
                name: "<whole file>".to_owned(),
                entropy: calculate_entropy(data),
                size: data.len() as u64,
            });
        }

        Ok(results)
    }
}

/// Compute Shannon entropy for a byte slice.
///
/// Formula: H = -Σ P(x) · log₂(P(x))
/// Result is in [0.0, 8.0] (8.0 = perfectly random / maximum entropy).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Frequency table for each possible byte value (0..=255)
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>()
        // Clamp to [0.0, 8.0] to guard against floating-point edge cases
        .clamp(0.0, 8.0)
}

#[cfg(test)]
mod tests {
    use super::calculate_entropy;

    #[test]
    fn zero_entropy_for_uniform_bytes() {
        // All same bytes → entropy = 0
        let data = vec![0u8; 1024];
        assert!((calculate_entropy(&data) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn max_entropy_for_random_distribution() {
        // All 256 distinct values, each appearing once → entropy = 8.0
        let data: Vec<u8> = (0..=255u8).collect();
        let h = calculate_entropy(&data);
        assert!((h - 8.0).abs() < 1e-10, "expected ~8.0, got {h}");
    }

    #[test]
    fn empty_slice_is_zero() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn result_within_range() {
        // Arbitrary bytes must always stay in [0, 8]
        let data: Vec<u8> = (0..1000).map(|i| (i * 7 % 256) as u8).collect();
        let h = calculate_entropy(&data);
        assert!((0.0..=8.0).contains(&h));
    }

    #[test]
    fn two_symbols_gives_one_bit() {
        // Equal mix of 0x00 and 0xFF → H = 1.0 bit
        let data: Vec<u8> = (0..1024)
            .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
            .collect();
        let h = calculate_entropy(&data);
        assert!((h - 1.0).abs() < 1e-10, "expected 1.0, got {h}");
    }

    #[test]
    fn single_byte_slice_is_zero() {
        assert_eq!(calculate_entropy(&[0x42]), 0.0);
    }

    #[test]
    fn high_entropy_exceeds_threshold() {
        // All 256 byte values present → entropy ~8.0, clearly above the 7.0 warn threshold
        let data: Vec<u8> = (0..=255u8).collect();
        assert!(calculate_entropy(&data) > 7.0);
    }

    #[test]
    fn low_entropy_text_like_data() {
        // ASCII-range only (32..=127): 96 distinct values, entropy < 8.0 but > 0.0
        let data: Vec<u8> = (0..512).map(|i| (32 + i % 96) as u8).collect();
        let h = calculate_entropy(&data);
        assert!(h > 0.0 && h < 8.0, "expected moderate entropy, got {h}");
    }

    #[test]
    fn monotone_increase_with_diversity() {
        // More distinct values → higher entropy
        let one = calculate_entropy(&[0u8; 256]);
        let two = calculate_entropy(&(0..256).map(|i| (i % 2) as u8).collect::<Vec<_>>());
        let four = calculate_entropy(&(0..256).map(|i| (i % 4) as u8).collect::<Vec<_>>());
        let all = calculate_entropy(&(0u8..=255).collect::<Vec<_>>());
        assert!(one < two, "1 symbol < 2 symbols");
        assert!(two < four, "2 symbols < 4 symbols");
        assert!(four < all, "4 symbols < 256 symbols");
    }
}
