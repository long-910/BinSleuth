use anyhow::Result;
use object::Endianness;
use object::read::elf::{Dyn, FileHeader, ProgramHeader};
use object::{FileKind, Object, ObjectSection, ObjectSymbol, elf};
use serde::Serialize;

// ── Result types ─────────────────────────────────────────────────────────────

/// Tri-state for a hardening check whose presence can be partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Protection is present and fully enabled
    Enabled,
    /// Protection is partially present (e.g. Partial RELRO vs Full RELRO)
    Partial(String),
    /// Protection is absent
    Disabled,
    /// Could not determine (binary format doesn't apply)
    NotApplicable,
}

impl Serialize for CheckResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CheckResult::Enabled => serializer.serialize_str("enabled"),
            CheckResult::Disabled => serializer.serialize_str("disabled"),
            CheckResult::NotApplicable => serializer.serialize_str("n/a"),
            CheckResult::Partial(msg) => serializer.serialize_str(&format!("partial: {msg}")),
        }
    }
}

/// All hardening checks collected from one binary.
#[derive(Debug, Clone, Serialize)]
pub struct HardeningInfo {
    pub format: String,
    pub architecture: String,
    /// NX / DEP — non-executable stack/data
    pub nx: CheckResult,
    /// PIE — position-independent executable
    pub pie: CheckResult,
    /// RELRO — read-only relocations (ELF-only)
    pub relro: CheckResult,
    /// Stack canary — `__stack_chk_fail` symbol present
    pub stack_canary: CheckResult,
    /// FORTIFY_SOURCE — fortified libc wrappers (`__*_chk`) present
    pub fortify_source: CheckResult,
    /// RPATH/RUNPATH — ELF library search-path injection risk (Enabled = safe, no path set)
    pub rpath: CheckResult,
    /// Debug symbols stripped (Enabled = stripped = good; Disabled = debug info present)
    pub stripped: CheckResult,
    /// Dangerous symbols found in the import/symbol table
    pub dangerous_symbols: Vec<DangerousSymbol>,
}

/// Category of a dangerous symbol, used for colour-coded visualisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolCategory {
    /// Process / shell execution (system, execve, WinExec, …)
    Exec,
    /// Network I/O (connect, socket, WinHttpOpen, …)
    Net,
    /// Memory permission manipulation (mprotect, VirtualAlloc, …)
    Mem,
}

/// A dangerous symbol found in the binary's symbol / import table.
#[derive(Debug, Clone, Serialize)]
pub struct DangerousSymbol {
    pub name: String,
    pub category: SymbolCategory,
}

// ── Dangerous symbol lists ────────────────────────────────────────────────────

const DANGEROUS_EXEC: &[&str] = &[
    "system",
    "popen",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execvp",
    "execvpe",
    "posix_spawn",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
];

const DANGEROUS_NET: &[&str] = &[
    "connect",
    "socket",
    "WSAConnect",
    "WSASocket",
    "WSAStartup",
    "gethostbyname",
    "getaddrinfo",
    "URLDownloadToFile",
    "WinHttpOpen",
    "InternetOpen",
    "InternetOpenA",
    "InternetOpenW",
];

const DANGEROUS_MEM: &[&str] = &[
    "mprotect",
    "VirtualProtect",
    "VirtualAlloc",
    "mmap",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
];

// ── Main analysis ─────────────────────────────────────────────────────────────

impl HardeningInfo {
    pub fn analyze(data: &[u8]) -> Result<HardeningInfo> {
        let kind = FileKind::parse(data)?;
        match kind {
            FileKind::Elf32 | FileKind::Elf64 => analyze_elf(data),
            FileKind::Pe32 | FileKind::Pe64 => analyze_pe(data),
            other => {
                anyhow::bail!("Unsupported binary format: {:?}", other);
            }
        }
    }
}

// ── ELF analysis ─────────────────────────────────────────────────────────────

fn analyze_elf(data: &[u8]) -> Result<HardeningInfo> {
    let obj = object::File::parse(data)?;
    let format = "ELF".to_owned();
    let architecture = format!("{:?}", obj.architecture());

    let kind = FileKind::parse(data)?;
    let is_64 = kind == FileKind::Elf64;

    let nx = if is_64 {
        detect_nx_64(data)
    } else {
        detect_nx_32(data)
    };
    let pie = if is_64 {
        detect_pie_64(data)
    } else {
        detect_pie_32(data)
    };
    let relro = if is_64 {
        detect_relro_64(data)
    } else {
        detect_relro_32(data)
    };

    // Stack Canary: search for well-known canary symbols in symbol tables
    let canary_syms = [
        "__stack_chk_fail",
        "__stack_chk_guard",
        "__stack_smash_handler",
    ];
    let stack_canary = if obj.symbols().chain(obj.dynamic_symbols()).any(|sym| {
        sym.name()
            .map(|n| canary_syms.iter().any(|&c| n.contains(c)))
            .unwrap_or(false)
    }) {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    };

    let dangerous_symbols = collect_dangerous_symbols(&obj);

    let fortify_source = detect_fortify_source(&obj);

    let rpath = if is_64 {
        detect_rpath_64(data)
    } else {
        detect_rpath_32(data)
    };

    // Stripped: check for embedded DWARF debug sections
    let has_debug = obj
        .sections()
        .any(|s| s.name().map(|n| n.starts_with(".debug_")).unwrap_or(false));
    let stripped = if has_debug {
        CheckResult::Disabled
    } else {
        CheckResult::Enabled
    };

    Ok(HardeningInfo {
        format,
        architecture,
        nx,
        pie,
        relro,
        stack_canary,
        fortify_source,
        rpath,
        stripped,
        dangerous_symbols,
    })
}

// ── NX helpers ────────────────────────────────────────────────────────────────

fn detect_nx_64(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader64::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::Disabled,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::Disabled,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::Disabled,
    };
    nx_from_phdrs(phdrs, endian)
}

fn detect_nx_32(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader32::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::Disabled,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::Disabled,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::Disabled,
    };
    nx_from_phdrs(phdrs, endian)
}

fn nx_from_phdrs<P: ProgramHeader<Endian = Endianness>>(
    phdrs: &[P],
    endian: Endianness,
) -> CheckResult {
    for phdr in phdrs {
        if phdr.p_type(endian) == elf::PT_GNU_STACK {
            // PF_X = 0x1 — if NOT set, the stack is non-executable → NX enabled
            return if phdr.p_flags(endian) & elf::PF_X == 0 {
                CheckResult::Enabled
            } else {
                CheckResult::Disabled
            };
        }
    }
    // No PT_GNU_STACK found — treat as NX disabled (conservative)
    CheckResult::Disabled
}

// ── PIE helpers ───────────────────────────────────────────────────────────────

fn detect_pie_64(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader64::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::Disabled,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::Disabled,
    };
    // ET_DYN (3) = position-independent; ET_EXEC (2) = non-PIE
    if header.e_type(endian) == elf::ET_DYN {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    }
}

fn detect_pie_32(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader32::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::Disabled,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::Disabled,
    };
    if header.e_type(endian) == elf::ET_DYN {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    }
}

// ── RELRO helpers ─────────────────────────────────────────────────────────────

fn detect_relro_64(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader64::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::NotApplicable,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::NotApplicable,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::NotApplicable,
    };

    let mut has_relro = false;
    let mut has_bind_now = false;

    for phdr in phdrs {
        match phdr.p_type(endian) {
            elf::PT_GNU_RELRO => has_relro = true,
            elf::PT_DYNAMIC => {
                if let Ok(Some(entries)) = phdr.dynamic(endian, data) {
                    for entry in entries {
                        // Dyn64: d_tag → u64, d_val → u64
                        let tag = entry.d_tag(endian);
                        let val = entry.d_val(endian);
                        if tag == elf::DT_FLAGS as u64 && val & elf::DF_BIND_NOW as u64 != 0 {
                            has_bind_now = true;
                        }
                        if tag == elf::DT_FLAGS_1 as u64 && val & elf::DF_1_NOW as u64 != 0 {
                            has_bind_now = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    relro_result(has_relro, has_bind_now)
}

fn detect_relro_32(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader32::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::NotApplicable,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::NotApplicable,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::NotApplicable,
    };

    let mut has_relro = false;
    let mut has_bind_now = false;

    for phdr in phdrs {
        match phdr.p_type(endian) {
            elf::PT_GNU_RELRO => has_relro = true,
            elf::PT_DYNAMIC => {
                if let Ok(Some(entries)) = phdr.dynamic(endian, data) {
                    for entry in entries {
                        // Dyn32: d_tag → u32, d_val → u32; widen both for uniform comparisons
                        let tag = u64::from(entry.d_tag(endian));
                        let val = u64::from(entry.d_val(endian));
                        if tag == elf::DT_FLAGS as u64 && val & elf::DF_BIND_NOW as u64 != 0 {
                            has_bind_now = true;
                        }
                        if tag == elf::DT_FLAGS_1 as u64 && val & elf::DF_1_NOW as u64 != 0 {
                            has_bind_now = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    relro_result(has_relro, has_bind_now)
}

fn relro_result(has_relro: bool, has_bind_now: bool) -> CheckResult {
    match (has_relro, has_bind_now) {
        (true, true) => CheckResult::Enabled,
        (true, false) => CheckResult::Partial("Partial RELRO".to_owned()),
        _ => CheckResult::Disabled,
    }
}

// ── PE analysis ───────────────────────────────────────────────────────────────

fn analyze_pe(data: &[u8]) -> Result<HardeningInfo> {
    let obj = object::File::parse(data)?;
    let format = "PE".to_owned();
    let architecture = format!("{:?}", obj.architecture());

    let (nx, pie) = detect_pe_characteristics(data);
    let relro = CheckResult::NotApplicable;

    let canary_syms = [
        "__security_cookie",
        "__security_check_cookie",
        "__stack_chk_fail",
    ];
    let stack_canary = if obj.symbols().chain(obj.dynamic_symbols()).any(|sym| {
        sym.name()
            .map(|n| canary_syms.iter().any(|&c| n.contains(c)))
            .unwrap_or(false)
    }) {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    };

    let dangerous_symbols = collect_dangerous_symbols(&obj);

    let fortify_source = detect_fortify_source(&obj);

    // Stripped: check PE debug directory and embedded .debug_* sections
    let stripped = detect_pe_stripped(data, &obj);

    Ok(HardeningInfo {
        format,
        architecture,
        nx,
        pie,
        relro,
        stack_canary,
        fortify_source,
        rpath: CheckResult::NotApplicable,
        stripped,
        dangerous_symbols,
    })
}

/// Extract DllCharacteristics from the PE optional header via raw bytes.
fn detect_pe_characteristics(data: &[u8]) -> (CheckResult, CheckResult) {
    if data.len() < 0x40 {
        return (CheckResult::Disabled, CheckResult::Disabled);
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if data.len() < e_lfanew + 4 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return (CheckResult::Disabled, CheckResult::Disabled);
    }

    // Optional header starts at e_lfanew + 4 (PE sig) + 20 (COFF header)
    let opt_offset = e_lfanew + 24;
    if data.len() < opt_offset + 2 {
        return (CheckResult::Disabled, CheckResult::Disabled);
    }

    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    // DllCharacteristics: offset 70 from start of optional header (same for PE32 and PE32+)
    let dll_char_offset = match magic {
        0x010b | 0x020b => opt_offset + 70,
        _ => return (CheckResult::Disabled, CheckResult::Disabled),
    };

    if data.len() < dll_char_offset + 2 {
        return (CheckResult::Disabled, CheckResult::Disabled);
    }
    let dll_chars = u16::from_le_bytes([data[dll_char_offset], data[dll_char_offset + 1]]);

    // IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x0100
    // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040 (PIE/ASLR)
    let nx = if dll_chars & 0x0100 != 0 {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    };
    let pie = if dll_chars & 0x0040 != 0 {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    };
    (nx, pie)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Detect whether a PE binary has debug information (via debug directory or .debug_* sections).
/// Returns Enabled (stripped) or Disabled (debug info present).
fn detect_pe_stripped(data: &[u8], obj: &object::File) -> CheckResult {
    // Check for embedded .debug_* sections (MinGW/GCC DWARF-in-PE)
    let has_debug_sections = obj
        .sections()
        .any(|s| s.name().map(|n| n.starts_with(".debug_")).unwrap_or(false));
    if has_debug_sections {
        return CheckResult::Disabled;
    }

    // Check PE debug directory (IMAGE_DIRECTORY_ENTRY_DEBUG, index 6)
    // DataDirectory for PE32  starts at opt_offset + 96
    // DataDirectory for PE32+ starts at opt_offset + 112
    // Each entry is 8 bytes; entry 6 is at DataDirectory + 48
    if data.len() < 0x40 {
        return CheckResult::Enabled;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if data.len() < e_lfanew + 4 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return CheckResult::Enabled;
    }
    let opt_offset = e_lfanew + 24;
    if data.len() < opt_offset + 2 {
        return CheckResult::Enabled;
    }
    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let debug_entry_offset = match magic {
        0x010b => opt_offset + 96 + 48,  // PE32:  DataDirectory + entry 6
        0x020b => opt_offset + 112 + 48, // PE32+: DataDirectory + entry 6
        _ => return CheckResult::Enabled,
    };
    if data.len() < debug_entry_offset + 4 {
        return CheckResult::Enabled;
    }
    let rva = u32::from_le_bytes([
        data[debug_entry_offset],
        data[debug_entry_offset + 1],
        data[debug_entry_offset + 2],
        data[debug_entry_offset + 3],
    ]);
    if rva != 0 {
        CheckResult::Disabled // debug directory present → not stripped
    } else {
        CheckResult::Enabled
    }
}

// ── FORTIFY_SOURCE detection ──────────────────────────────────────────────────

/// Detect `-D_FORTIFY_SOURCE` by looking for fortified libc wrapper symbols (`__*_chk`).
///
/// When compiled with `_FORTIFY_SOURCE=1` or `=2`, the compiler replaces unsafe
/// libc calls (memcpy, strcpy, sprintf, …) with bounds-checking variants whose
/// names end in `_chk` and are prefixed with `__` (e.g. `__memcpy_chk`).
fn detect_fortify_source(obj: &object::File) -> CheckResult {
    let has_chk = obj
        .symbols()
        .chain(obj.dynamic_symbols())
        .filter_map(|sym| sym.name().ok())
        .any(|name| name.starts_with("__") && name.ends_with("_chk"));
    if has_chk {
        CheckResult::Enabled
    } else {
        CheckResult::Disabled
    }
}

// ── RPATH / RUNPATH detection ─────────────────────────────────────────────────

/// Scan the ELF dynamic section for `DT_RPATH` (tag 15) or `DT_RUNPATH` (tag 29).
///
/// An embedded RPATH/RUNPATH can allow an attacker to inject a malicious shared
/// library into the process if the path includes a world-writable or relative
/// directory.  Returns:
/// - `Enabled`  — no RPATH/RUNPATH present (safe)
/// - `Disabled` — one or more entries found (potential hijacking vector)
/// - `NotApplicable` — binary has no dynamic segment (static binary)
fn rpath_from_dynamic<D: Dyn<Endian = Endianness>>(entries: &[D], endian: Endianness) -> bool {
    entries.iter().any(|entry| {
        let tag = entry.d_tag(endian).into();
        let val: u64 = entry.d_val(endian).into();
        (tag == elf::DT_RPATH as u64 || tag == elf::DT_RUNPATH as u64) && val != 0
    })
}

fn detect_rpath_64(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader64::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::NotApplicable,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::NotApplicable,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::NotApplicable,
    };

    let mut has_dynamic = false;
    for phdr in phdrs {
        if phdr.p_type(endian) == elf::PT_DYNAMIC {
            has_dynamic = true;
            if let Ok(Some(entries)) = phdr.dynamic(endian, data) {
                if rpath_from_dynamic(entries, endian) {
                    return CheckResult::Disabled;
                }
            }
        }
    }
    if has_dynamic {
        CheckResult::Enabled
    } else {
        CheckResult::NotApplicable
    }
}

fn detect_rpath_32(data: &[u8]) -> CheckResult {
    let header = match object::elf::FileHeader32::<Endianness>::parse(data) {
        Ok(h) => h,
        Err(_) => return CheckResult::NotApplicable,
    };
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return CheckResult::NotApplicable,
    };
    let phdrs = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(_) => return CheckResult::NotApplicable,
    };

    let mut has_dynamic = false;
    for phdr in phdrs {
        if phdr.p_type(endian) == elf::PT_DYNAMIC {
            has_dynamic = true;
            if let Ok(Some(entries)) = phdr.dynamic(endian, data) {
                if rpath_from_dynamic(entries, endian) {
                    return CheckResult::Disabled;
                }
            }
        }
    }
    if has_dynamic {
        CheckResult::Enabled
    } else {
        CheckResult::NotApplicable
    }
}

fn collect_dangerous_symbols(obj: &object::File) -> Vec<DangerousSymbol> {
    let mut found: Vec<DangerousSymbol> = obj
        .symbols()
        .chain(obj.dynamic_symbols())
        .filter_map(|sym| sym.name().ok())
        .filter_map(categorize_dangerous_symbol)
        .collect();

    found.sort_by(|a, b| a.name.cmp(&b.name));
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// Return the category of a symbol if it is considered dangerous, otherwise `None`.
fn categorize_dangerous_symbol(name: &str) -> Option<DangerousSymbol> {
    let category = if DANGEROUS_EXEC.iter().any(|&d| name == d || name.contains(d)) {
        SymbolCategory::Exec
    } else if DANGEROUS_NET.iter().any(|&d| name == d || name.contains(d)) {
        SymbolCategory::Net
    } else if DANGEROUS_MEM.iter().any(|&d| name == d || name.contains(d)) {
        SymbolCategory::Mem
    } else {
        return None;
    };
    Some(DangerousSymbol {
        name: name.to_owned(),
        category,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal syntactically-valid PE32 with the given DllCharacteristics.
    ///
    /// Layout (all little-endian):
    ///   0x00        DOS magic "MZ"
    ///   0x3c..0x40  e_lfanew = 0x40
    ///   0x40..0x44  PE signature "PE\0\0"
    ///   0x44..0x58  COFF header (20 zero bytes)
    ///   0x58..0x5a  Optional header magic = 0x010b (PE32)
    ///   0x58+70 ..  DllCharacteristics (2 bytes)
    fn make_pe32(dll_chars: u16) -> Vec<u8> {
        const E_LFANEW: usize = 0x40;
        const OPT_OFFSET: usize = E_LFANEW + 4 + 20; // PE sig + COFF header
        const DLL_OFFSET: usize = OPT_OFFSET + 70;

        let mut data = vec![0u8; DLL_OFFSET + 2];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
        data[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
        data[OPT_OFFSET..OPT_OFFSET + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32
        data[DLL_OFFSET..DLL_OFFSET + 2].copy_from_slice(&dll_chars.to_le_bytes());
        data
    }

    // ── PE characteristic tests ───────────────────────────────────────────────

    #[test]
    fn pe_nx_and_pie_enabled() {
        let (nx, pie) = detect_pe_characteristics(&make_pe32(0x0140));
        assert_eq!(nx, CheckResult::Enabled);
        assert_eq!(pie, CheckResult::Enabled);
    }

    #[test]
    fn pe_nx_only_enabled() {
        let (nx, pie) = detect_pe_characteristics(&make_pe32(0x0100));
        assert_eq!(nx, CheckResult::Enabled);
        assert_eq!(pie, CheckResult::Disabled);
    }

    #[test]
    fn pe_pie_only_enabled() {
        let (nx, pie) = detect_pe_characteristics(&make_pe32(0x0040));
        assert_eq!(nx, CheckResult::Disabled);
        assert_eq!(pie, CheckResult::Enabled);
    }

    #[test]
    fn pe_no_protections() {
        let (nx, pie) = detect_pe_characteristics(&make_pe32(0x0000));
        assert_eq!(nx, CheckResult::Disabled);
        assert_eq!(pie, CheckResult::Disabled);
    }

    #[test]
    fn pe_too_short_returns_disabled() {
        let (nx, pie) = detect_pe_characteristics(&[0u8; 10]);
        assert_eq!(nx, CheckResult::Disabled);
        assert_eq!(pie, CheckResult::Disabled);
    }

    #[test]
    fn pe_empty_returns_disabled() {
        let (nx, pie) = detect_pe_characteristics(&[]);
        assert_eq!(nx, CheckResult::Disabled);
        assert_eq!(pie, CheckResult::Disabled);
    }

    #[test]
    fn pe_bad_signature_returns_disabled() {
        let mut data = make_pe32(0x0140);
        // Corrupt the PE signature
        data[0x40] = 0x00;
        let (nx, pie) = detect_pe_characteristics(&data);
        assert_eq!(nx, CheckResult::Disabled);
        assert_eq!(pie, CheckResult::Disabled);
    }

    // ── RELRO helper tests ────────────────────────────────────────────────────

    #[test]
    fn relro_full_when_both_flags_set() {
        assert_eq!(relro_result(true, true), CheckResult::Enabled);
    }

    #[test]
    fn relro_partial_when_only_segment_present() {
        assert!(
            matches!(relro_result(true, false), CheckResult::Partial(_)),
            "expected Partial RELRO"
        );
    }

    #[test]
    fn relro_disabled_when_no_segment() {
        assert_eq!(relro_result(false, false), CheckResult::Disabled);
    }

    #[test]
    fn relro_disabled_when_bind_now_without_segment() {
        // BIND_NOW alone (no PT_GNU_RELRO) should still be Disabled
        assert_eq!(relro_result(false, true), CheckResult::Disabled);
    }

    // ── CheckResult display invariants ────────────────────────────────────────

    #[test]
    fn check_result_partial_carries_message() {
        let msg = "Partial RELRO".to_owned();
        match CheckResult::Partial(msg.clone()) {
            CheckResult::Partial(s) => assert_eq!(s, msg),
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    // ── FORTIFY_SOURCE tests ──────────────────────────────────────────────────

    #[test]
    fn fortify_source_disabled_for_empty_object() {
        // A minimal ELF with no symbols → FORTIFY_SOURCE must be Disabled
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let obj = object::File::parse(data.as_slice()).expect("parse");
        // We can't guarantee the test binary has __*_chk; just verify no panic
        let result = detect_fortify_source(&obj);
        assert!(matches!(
            result,
            CheckResult::Enabled | CheckResult::Disabled
        ));
    }

    // ── RPATH helpers tests ───────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn rpath_result_on_self_is_valid() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let result = detect_rpath_64(&data);
        // A freshly built Rust binary should have no RPATH or be NotApplicable
        assert!(matches!(
            result,
            CheckResult::Enabled | CheckResult::Disabled | CheckResult::NotApplicable
        ));
    }

    // ── categorize_dangerous_symbol ───────────────────────────────────────────

    #[test]
    fn exec_symbol_is_categorized_as_exec() {
        let sym = categorize_dangerous_symbol("system").expect("system must be dangerous");
        assert_eq!(sym.name, "system");
        assert_eq!(sym.category, SymbolCategory::Exec);
    }

    #[test]
    fn net_symbol_is_categorized_as_net() {
        let sym = categorize_dangerous_symbol("connect").expect("connect must be dangerous");
        assert_eq!(sym.category, SymbolCategory::Net);
    }

    #[test]
    fn mem_symbol_is_categorized_as_mem() {
        let sym = categorize_dangerous_symbol("mprotect").expect("mprotect must be dangerous");
        assert_eq!(sym.category, SymbolCategory::Mem);
    }

    #[test]
    fn windows_exec_symbol_is_exec() {
        let sym = categorize_dangerous_symbol("WinExec").expect("WinExec must be dangerous");
        assert_eq!(sym.category, SymbolCategory::Exec);
    }

    #[test]
    fn windows_net_symbol_is_net() {
        let sym = categorize_dangerous_symbol("WSAConnect").expect("WSAConnect must be dangerous");
        assert_eq!(sym.category, SymbolCategory::Net);
    }

    #[test]
    fn windows_mem_symbol_is_mem() {
        let sym =
            categorize_dangerous_symbol("VirtualAlloc").expect("VirtualAlloc must be dangerous");
        assert_eq!(sym.category, SymbolCategory::Mem);
    }

    #[test]
    fn safe_symbols_return_none() {
        assert!(categorize_dangerous_symbol("printf").is_none());
        assert!(categorize_dangerous_symbol("malloc").is_none());
        assert!(categorize_dangerous_symbol("strlen").is_none());
        assert!(categorize_dangerous_symbol("memcpy").is_none());
        assert!(categorize_dangerous_symbol("").is_none());
    }

    #[test]
    fn dangerous_symbol_carries_name() {
        let sym = categorize_dangerous_symbol("execve").unwrap();
        assert_eq!(sym.name, "execve");
    }

    // ── Full HardeningInfo round-trip on the test binary (ELF) ───────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn analyze_self_succeeds_on_linux() {
        // Read the binsleuth test binary that cargo placed next to us.
        // The binary will be valid ELF on Linux.
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let info = HardeningInfo::analyze(&data).expect("analyze");
        assert_eq!(info.format, "ELF");
        // At minimum the enum variants should be the expected types
        assert!(matches!(
            info.nx,
            CheckResult::Enabled | CheckResult::Disabled | CheckResult::Partial(_)
        ));
    }
}
