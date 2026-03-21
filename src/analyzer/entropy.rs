use anyhow::Result;
use object::{Object, ObjectSection, SectionFlags};
use serde::Serialize;

/// Read / write / execute permissions extracted from a section's flags.
#[derive(Debug, Clone, Serialize)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Shannon entropy result for a single binary section.
#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    /// Section name (e.g. `.text`, `.data`, `UPX0`)
    pub name: String,
    /// Virtual address where the section is loaded (0 for unmapped sections)
    pub virtual_address: u64,
    /// Offset of the section data within the file (0 if not stored on disk)
    pub file_offset: u64,
    /// Raw byte size of the section
    pub size: u64,
    /// Computed entropy in [0.0, 8.0]
    pub entropy: f64,
    /// Read / write / execute flags (derived from section flags)
    pub permissions: SectionPermissions,
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
            let virtual_address = section.address();
            let file_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
            let permissions = extract_permissions(section.flags());
            results.push(SectionEntropy {
                name,
                virtual_address,
                file_offset,
                size,
                entropy,
                permissions,
            });
        }

        // If the object format exposes no sections (some PE/raw blobs),
        // fall back to whole-file entropy.
        if results.is_empty() {
            results.push(SectionEntropy {
                name: "<whole file>".to_owned(),
                virtual_address: 0,
                file_offset: 0,
                size: data.len() as u64,
                entropy: calculate_entropy(data),
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            });
        }

        Ok(results)
    }
}

/// Derive read/write/execute permissions from raw section flags.
///
/// ELF: uses `SHF_ALLOC` (0x2 = readable/mapped), `SHF_WRITE` (0x1), `SHF_EXECINSTR` (0x4).
/// PE/COFF: uses `IMAGE_SCN_MEM_READ` (0x4000_0000), `IMAGE_SCN_MEM_WRITE` (0x8000_0000),
///           `IMAGE_SCN_MEM_EXECUTE` (0x2000_0000).
fn extract_permissions(flags: SectionFlags) -> SectionPermissions {
    match flags {
        SectionFlags::Elf { sh_flags } => SectionPermissions {
            read: sh_flags & 0x2 != 0,    // SHF_ALLOC → mapped → readable
            write: sh_flags & 0x1 != 0,   // SHF_WRITE
            execute: sh_flags & 0x4 != 0, // SHF_EXECINSTR
        },
        SectionFlags::Coff { characteristics } => SectionPermissions {
            read: characteristics & 0x4000_0000 != 0, // IMAGE_SCN_MEM_READ
            write: characteristics & 0x8000_0000 != 0, // IMAGE_SCN_MEM_WRITE
            execute: characteristics & 0x2000_0000 != 0, // IMAGE_SCN_MEM_EXECUTE
        },
        _ => SectionPermissions {
            read: false,
            write: false,
            execute: false,
        },
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
    use super::{SectionEntropy, calculate_entropy, extract_permissions};
    use object::SectionFlags;

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

    // ── extract_permissions ───────────────────────────────────────────────────

    #[test]
    fn elf_rw_section() {
        // SHF_ALLOC (0x2) | SHF_WRITE (0x1)
        let p = extract_permissions(SectionFlags::Elf { sh_flags: 0x3 });
        assert!(p.read, "SHF_ALLOC → readable");
        assert!(p.write, "SHF_WRITE → writable");
        assert!(!p.execute);
    }

    #[test]
    fn elf_rx_section() {
        // SHF_ALLOC (0x2) | SHF_EXECINSTR (0x4)
        let p = extract_permissions(SectionFlags::Elf { sh_flags: 0x6 });
        assert!(p.read);
        assert!(!p.write);
        assert!(p.execute, "SHF_EXECINSTR → executable");
    }

    #[test]
    fn elf_non_alloc_section_not_readable() {
        // No SHF_ALLOC → not mapped → not readable
        let p = extract_permissions(SectionFlags::Elf { sh_flags: 0x0 });
        assert!(!p.read);
        assert!(!p.write);
        assert!(!p.execute);
    }

    #[test]
    fn coff_read_execute_section() {
        // IMAGE_SCN_MEM_READ (0x4000_0000) | IMAGE_SCN_MEM_EXECUTE (0x2000_0000)
        let p = extract_permissions(SectionFlags::Coff {
            characteristics: 0x6000_0000,
        });
        assert!(p.read);
        assert!(!p.write);
        assert!(p.execute);
    }

    #[test]
    fn coff_rw_section() {
        // IMAGE_SCN_MEM_READ (0x4000_0000) | IMAGE_SCN_MEM_WRITE (0x8000_0000)
        let p = extract_permissions(SectionFlags::Coff {
            characteristics: 0xC000_0000,
        });
        assert!(p.read);
        assert!(p.write);
        assert!(!p.execute);
    }

    #[test]
    fn unknown_flags_are_all_false() {
        let p = extract_permissions(SectionFlags::None);
        assert!(!p.read);
        assert!(!p.write);
        assert!(!p.execute);
    }

    // ── SectionEntropy::analyze new fields ───────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn analyze_self_sections_have_valid_metadata() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let sections = SectionEntropy::analyze(&data).expect("analyze");

        assert!(!sections.is_empty(), "expected at least one section");

        // Every section must have a non-empty name
        assert!(sections.iter().all(|s| !s.name.is_empty()));

        // .text must be executable and have a non-zero virtual address
        if let Some(text) = sections.iter().find(|s| s.name == ".text") {
            assert!(text.permissions.execute, ".text must be executable");
            assert!(
                text.virtual_address > 0,
                ".text must have a non-zero virtual address"
            );
            assert!(text.size > 0, ".text must have non-zero size");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn analyze_self_section_sizes_match_entropy_domain() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let sections = SectionEntropy::analyze(&data).expect("analyze");

        for sec in &sections {
            assert!(
                sec.size > 0,
                "section '{}' has zero size after filtering",
                sec.name
            );
            assert!(
                (0.0..=8.0).contains(&sec.entropy),
                "section '{}' entropy {} out of [0,8]",
                sec.name,
                sec.entropy
            );
        }
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
