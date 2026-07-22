use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::thread;

fn usage() -> ! {
    eprintln!(
        "usage:
  libc_tool_core extract-abi-tokens [PREFIX...]
  libc_tool_core filter-package-urls <repo_root> <arch> <package_csv> [package_version] [package_filename]
  libc_tool_core inspect-elf <path>
  libc_tool_core build-index <db_path> <schema_version> <common_symbol_csv>"
    );
    process::exit(2);
}

fn read_stdin_to_string() -> String {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {err}");
        process::exit(1);
    }
    input
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_option_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn read_u16(data: &[u8], offset: usize, le: bool) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(if le {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    })
}

fn read_u32(data: &[u8], offset: usize, le: bool) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(if le {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

fn read_u64(data: &[u8], offset: usize, le: bool) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(if le {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    } else {
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn cstr_at(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let tail = &data[offset..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..end]).to_string())
}

#[derive(Clone, Debug)]
struct ElfSection {
    name_offset: u32,
    section_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

#[derive(Clone, Debug)]
struct ElfInfo {
    build_id: Option<String>,
    arch: String,
    has_dynamic: bool,
    has_debug: bool,
    needed: Vec<String>,
}

fn parse_note_build_id(note_data: &[u8], le: bool) -> Option<String> {
    let mut offset = 0usize;
    while offset + 12 <= note_data.len() {
        let namesz = read_u32(note_data, offset, le)? as usize;
        let descsz = read_u32(note_data, offset + 4, le)? as usize;
        let note_type = read_u32(note_data, offset + 8, le)?;
        offset += 12;
        let name_end = offset.checked_add(namesz)?;
        if name_end > note_data.len() {
            return None;
        }
        let name = &note_data[offset..name_end];
        offset = align4(name_end);
        let desc_end = offset.checked_add(descsz)?;
        if desc_end > note_data.len() {
            return None;
        }
        let desc = &note_data[offset..desc_end];
        offset = align4(desc_end);
        if note_type == 3 && (name == b"GNU\0" || name == b"GNU") {
            return Some(bytes_to_hex(desc));
        }
    }
    None
}

fn machine_to_arch(machine: u16, class: u8) -> &'static str {
    match machine {
        3 => "i386",
        40 => "arm",
        62 if class == 1 => "x32",
        62 => "amd64",
        183 => "aarch64",
        _ => "unknown",
    }
}

fn parse_elf_sections(data: &[u8], class: u8, le: bool) -> Vec<ElfSection> {
    let (shoff, shentsize, shnum) = if class == 1 {
        (
            read_u32(data, 32, le).map(u64::from).unwrap_or(0),
            read_u16(data, 46, le).unwrap_or(0),
            read_u16(data, 48, le).unwrap_or(0),
        )
    } else {
        (
            read_u64(data, 40, le).unwrap_or(0),
            read_u16(data, 58, le).unwrap_or(0),
            read_u16(data, 60, le).unwrap_or(0),
        )
    };
    if shoff == 0 || shentsize == 0 || shnum == 0 {
        return Vec::new();
    }

    let mut sections = Vec::new();
    for index in 0..shnum as usize {
        let Some(base) = (shoff as usize).checked_add(index * shentsize as usize) else {
            break;
        };
        if base + shentsize as usize > data.len() {
            break;
        }
        let name_offset = read_u32(data, base, le).unwrap_or(0);
        let section_type = read_u32(data, base + 4, le).unwrap_or(0);
        let (offset, size, link, entsize) = if class == 1 {
            (
                read_u32(data, base + 16, le).map(u64::from).unwrap_or(0),
                read_u32(data, base + 20, le).map(u64::from).unwrap_or(0),
                read_u32(data, base + 24, le).unwrap_or(0),
                read_u32(data, base + 36, le).map(u64::from).unwrap_or(0),
            )
        } else {
            (
                read_u64(data, base + 24, le).unwrap_or(0),
                read_u64(data, base + 32, le).unwrap_or(0),
                read_u32(data, base + 40, le).unwrap_or(0),
                read_u64(data, base + 56, le).unwrap_or(0),
            )
        };
        sections.push(ElfSection {
            name_offset,
            section_type,
            offset,
            size,
            link,
            entsize,
        });
    }
    sections
}

fn parse_needed_from_dynamic_section(
    data: &[u8],
    sections: &[ElfSection],
    section: &ElfSection,
    class: u8,
    le: bool,
) -> Vec<String> {
    let Some(strtab) = sections.get(section.link as usize) else {
        return Vec::new();
    };
    let Some(dynamic_data) =
        data.get(section.offset as usize..(section.offset + section.size) as usize)
    else {
        return Vec::new();
    };
    let Some(strtab_data) =
        data.get(strtab.offset as usize..(strtab.offset + strtab.size) as usize)
    else {
        return Vec::new();
    };
    let entry_size = if section.entsize != 0 {
        section.entsize as usize
    } else if class == 1 {
        8
    } else {
        16
    };
    let mut needed = Vec::new();
    let mut offset = 0usize;
    while offset + entry_size <= dynamic_data.len() {
        let tag = if class == 1 {
            read_u32(dynamic_data, offset, le)
                .map(i64::from)
                .unwrap_or(0)
        } else {
            read_u64(dynamic_data, offset, le)
                .map(|value| value as i64)
                .unwrap_or(0)
        };
        if tag == 0 {
            break;
        }
        if tag == 1 {
            let value = if class == 1 {
                read_u32(dynamic_data, offset + 4, le)
                    .map(u64::from)
                    .unwrap_or(0)
            } else {
                read_u64(dynamic_data, offset + 8, le).unwrap_or(0)
            };
            if let Some(name) = cstr_at(strtab_data, value as usize) {
                if !name.is_empty() && !needed.contains(&name) {
                    needed.push(name);
                }
            }
        }
        offset += entry_size;
    }
    needed
}

fn parse_elf_info(path: &Path) -> Option<ElfInfo> {
    let data = fs::read(path).ok()?;
    if data.len() < 64 || data.get(0..4)? != b"\x7fELF" {
        return None;
    }
    let class = *data.get(4)?;
    let le = match data.get(5).copied()? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let machine = read_u16(&data, 18, le).unwrap_or(0);
    let arch = machine_to_arch(machine, class).to_string();
    let sections = parse_elf_sections(&data, class, le);

    let shstrndx = if class == 1 {
        read_u16(&data, 50, le).unwrap_or(0)
    } else {
        read_u16(&data, 62, le).unwrap_or(0)
    };
    let shstr = sections.get(shstrndx as usize).and_then(|section| {
        data.get(section.offset as usize..(section.offset + section.size) as usize)
    });

    let mut build_id = None;
    let mut has_dynamic = false;
    let mut has_debug = false;
    let mut needed = Vec::new();

    for section in &sections {
        let name = shstr
            .and_then(|strings| cstr_at(strings, section.name_offset as usize))
            .unwrap_or_default();
        if section.section_type == 6 || name == ".dynamic" {
            has_dynamic = true;
            for item in parse_needed_from_dynamic_section(&data, &sections, section, class, le) {
                if !needed.contains(&item) {
                    needed.push(item);
                }
            }
        }
        if name == ".debug_info" || name == ".symtab" {
            has_debug = true;
        }
        if build_id.is_none() && section.section_type == 7 {
            if let Some(note_data) =
                data.get(section.offset as usize..(section.offset + section.size) as usize)
            {
                build_id = parse_note_build_id(note_data, le);
            }
        }
    }

    let (phoff, phentsize, phnum) = if class == 1 {
        (
            read_u32(&data, 28, le).map(u64::from).unwrap_or(0),
            read_u16(&data, 42, le).unwrap_or(0),
            read_u16(&data, 44, le).unwrap_or(0),
        )
    } else {
        (
            read_u64(&data, 32, le).unwrap_or(0),
            read_u16(&data, 54, le).unwrap_or(0),
            read_u16(&data, 56, le).unwrap_or(0),
        )
    };
    for index in 0..phnum as usize {
        let Some(base) = (phoff as usize).checked_add(index * phentsize as usize) else {
            break;
        };
        if base + phentsize as usize > data.len() {
            break;
        }
        let p_type = read_u32(&data, base, le).unwrap_or(0);
        if p_type == 2 {
            has_dynamic = true;
        }
        if build_id.is_none() && p_type == 4 {
            let (offset, filesz) = if class == 1 {
                (
                    read_u32(&data, base + 4, le).map(u64::from).unwrap_or(0),
                    read_u32(&data, base + 16, le).map(u64::from).unwrap_or(0),
                )
            } else {
                (
                    read_u64(&data, base + 8, le).unwrap_or(0),
                    read_u64(&data, base + 32, le).unwrap_or(0),
                )
            };
            if let Some(note_data) = data.get(offset as usize..(offset + filesz) as usize) {
                build_id = parse_note_build_id(note_data, le);
            }
        }
    }

    Some(ElfInfo {
        build_id,
        arch,
        has_dynamic,
        has_debug,
        needed,
    })
}

fn inspect_elf(args: &[String]) {
    if args.len() != 2 {
        usage();
    }
    let Some(info) = parse_elf_info(Path::new(&args[1])) else {
        println!(
            "{{\"build_id\":null,\"arch\":\"unknown\",\"has_dynamic\":false,\"has_debug\":false,\"needed\":[]}}"
        );
        return;
    };
    let needed = info
        .needed
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"build_id\":{},\"arch\":{},\"has_dynamic\":{},\"has_debug\":{},\"needed\":[{}]}}",
        json_option_string(info.build_id.as_deref()),
        json_string(&info.arch),
        if info.has_dynamic { "true" } else { "false" },
        if info.has_debug { "true" } else { "false" },
        needed
    );
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
}

fn token_has_valid_suffix(token: &str, prefix: &str) -> bool {
    let suffix = &token[prefix.len()..];
    if prefix == "GLIBC_" && suffix.starts_with("ABI_") {
        return suffix[4..]
            .bytes()
            .next()
            .map(|b| b.is_ascii_alphanumeric() || b == b'_')
            .unwrap_or(false);
    }
    suffix
        .bytes()
        .next()
        .map(|b| b.is_ascii_digit())
        .unwrap_or(false)
}

fn extract_abi_tokens(text: &str, prefixes: &[String]) -> Vec<String> {
    const ALL_PREFIXES: [&str; 4] = ["GLIBCXX_", "CXXABI_", "GCC_", "GLIBC_"];
    let active: Vec<&str> = if prefixes.is_empty() {
        ALL_PREFIXES.to_vec()
    } else {
        prefixes.iter().map(String::as_str).collect()
    };
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let prefix = active.iter().find(|prefix| text[i..].starts_with(**prefix));
        let Some(prefix) = prefix else {
            i += 1;
            continue;
        };
        if i > 0 && is_token_char(bytes[i - 1]) {
            i += 1;
            continue;
        }
        let mut end = i + prefix.len();
        while end < bytes.len() && is_token_char(bytes[end]) {
            end += 1;
        }
        let token = &text[i..end];
        if token_has_valid_suffix(token, prefix) && seen.insert(token.to_string()) {
            result.push(token.to_string());
        }
        i = end.max(i + 1);
    }
    result.sort_by(|left, right| abi_version_sort_key(left).cmp(&abi_version_sort_key(right)));
    result
}

fn abi_version_sort_key(token: &str) -> Vec<(u8, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut current_digit = None;
    for ch in token.chars() {
        let is_digit = ch.is_ascii_digit();
        match current_digit {
            Some(kind) if kind == is_digit => current.push(ch),
            Some(kind) => {
                parts.push(sort_part(kind, &current));
                current.clear();
                current.push(ch);
                current_digit = Some(is_digit);
            }
            None => {
                current.push(ch);
                current_digit = Some(is_digit);
            }
        }
    }
    if let Some(kind) = current_digit {
        parts.push(sort_part(kind, &current));
    }
    parts
}

fn sort_part(is_digit: bool, value: &str) -> (u8, String) {
    if is_digit {
        let normalized = value.trim_start_matches('0');
        let normalized = if normalized.is_empty() {
            "0"
        } else {
            normalized
        };
        (0, format!("{:0>20}", normalized))
    } else {
        (1, value.to_string())
    }
}

fn parse_control_entries(text: &str) -> Vec<HashMap<String, String>> {
    let mut entries = Vec::new();
    let mut entry: HashMap<String, String> = HashMap::new();
    let mut current_key: Option<String> = None;

    for line in text.lines() {
        if line.is_empty() {
            if !entry.is_empty() {
                entries.push(entry);
                entry = HashMap::new();
                current_key = None;
            }
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(key) = current_key.as_ref() {
                entry.entry(key.clone()).and_modify(|value: &mut String| {
                    value.push('\n');
                    value.push_str(line.trim_start());
                });
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_string();
        entry.insert(key.clone(), value.trim().to_string());
        current_key = Some(key);
    }
    if !entry.is_empty() {
        entries.push(entry);
    }
    entries
}

fn filter_package_urls(args: &[String]) {
    if args.len() < 5 {
        usage();
    }
    let repo_root = &args[1];
    let arch = &args[2];
    let package_names: Vec<String> = args[3]
        .split(',')
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let package_version = args.get(4).filter(|value| !value.is_empty());
    let package_filename = args.get(5).filter(|value| !value.is_empty());

    let wanted: HashSet<&str> = package_names.iter().map(String::as_str).collect();
    let package_order: HashMap<&str, usize> = package_names
        .iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect();
    let input = read_stdin_to_string();
    let mut matches = Vec::new();

    for entry in parse_control_entries(&input) {
        let Some(package) = entry.get("Package") else {
            continue;
        };
        if !wanted.contains(package.as_str()) {
            continue;
        }
        let Some(entry_arch) = entry.get("Architecture") else {
            continue;
        };
        if entry_arch != arch && entry_arch != "all" {
            continue;
        }
        if let Some(version) = package_version {
            if entry.get("Version") != Some(version) {
                continue;
            }
        }
        let Some(filename) = entry.get("Filename") else {
            continue;
        };
        if let Some(wanted_filename) = package_filename {
            if filename.rsplit('/').next() != Some(wanted_filename.as_str()) {
                continue;
            }
        }
        let package_rank = *package_order
            .get(package.as_str())
            .unwrap_or(&package_order.len());
        let arch_score = if entry_arch == arch { 0 } else { 1 };
        matches.push((
            package_rank,
            arch_score,
            package.clone(),
            entry.get("Version").cloned().unwrap_or_default(),
            entry_arch.clone(),
            filename.clone(),
            entry.get("SHA256").cloned().unwrap_or_default(),
            entry.get("Size").cloned().unwrap_or_default(),
        ));
    }

    matches.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let mut seen = HashSet::new();
    for (
        _package_rank,
        _arch_score,
        package,
        version,
        entry_arch,
        filename,
        sha256,
        size,
    ) in matches
    {
        let url = format!(
            "{}/{}",
            repo_root.trim_end_matches('/'),
            filename.trim_start_matches('/')
        );
        if seen.insert(url.clone()) {
            println!(
                "{{\"package_url\":{},\"package_name\":{},\"package_version\":{},\"package_arch\":{},\"package_filename\":{},\"package_sha256\":{},\"package_size\":{}}}",
                json_string(&url),
                json_string(&package),
                json_string(&version),
                json_string(&entry_arch),
                json_string(filename.rsplit('/').next().unwrap_or(filename.as_str())),
                json_string(&sha256),
                json_string(&size),
            );
        }
    }
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let base = i * 4;
            *word = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn sha1_hex_file(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|data| bytes_to_hex(&sha1_digest(&data)))
}

fn parse_filename_id(file_name: &str) -> (Option<String>, Option<String>) {
    let base = file_name.strip_suffix(".so").unwrap_or(file_name);
    let mut version = None;
    if let Some(start) = base.find('_') {
        let rest = &base[start + 1..];
        let candidate: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
            .collect();
        if candidate.matches('.').count() >= 1
            && candidate
                .chars()
                .next()
                .map(|ch| ch.is_ascii_digit())
                .unwrap_or(false)
        {
            version = Some(candidate);
        }
    }

    let mut arch = None;
    for arch_name in ["amd64", "i386", "x32", "arm", "aarch64", "armhf", "armel"] {
        if base.ends_with(arch_name) || base.ends_with(&format!("{arch_name}_2")) {
            arch = Some(arch_name.to_string());
            break;
        }
    }
    (version, arch)
}

fn load_symbol_suffixes(
    symbols_path: &Path,
    common_symbols: &[String],
) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let Ok(text) = fs::read_to_string(symbols_path) else {
        return result;
    };
    let mut remaining: HashSet<&str> = common_symbols.iter().map(String::as_str).collect();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(symbol_name) = parts.next() else {
            continue;
        };
        let Some(symbol_addr) = parts.next() else {
            continue;
        };
        if !remaining.contains(symbol_name) {
            continue;
        }
        let suffix = if symbol_addr.len() > 3 {
            &symbol_addr[symbol_addr.len() - 3..]
        } else {
            symbol_addr
        };
        result.insert(symbol_name.to_string(), suffix.to_ascii_lowercase());
        remaining.remove(symbol_name);
        if remaining.is_empty() {
            break;
        }
    }
    result
}

#[derive(Clone)]
struct IndexEntry {
    id: String,
    path: String,
    build_id: Option<String>,
    sha1: String,
    arch: String,
    version: Option<String>,
    info: String,
    package_url: Option<String>,
    symbol_suffixes: BTreeMap<String, String>,
}

fn build_index_entry(
    db_path: &Path,
    so_file: &str,
    common_symbols: &[String],
) -> Option<IndexEntry> {
    let so_path = db_path.join(so_file);
    let entry_id = so_file.strip_suffix(".so").unwrap_or(so_file).to_string();
    let info = fs::read_to_string(db_path.join(format!("{entry_id}.info")))
        .unwrap_or_default()
        .trim()
        .to_string();
    let package_url = fs::read_to_string(db_path.join(format!("{entry_id}.url")))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let symbol_suffixes =
        load_symbol_suffixes(&db_path.join(format!("{entry_id}.symbols")), common_symbols);
    let elf_info = parse_elf_info(&so_path);
    let (version, file_arch) = parse_filename_id(so_file);
    let arch = elf_info
        .as_ref()
        .map(|info| info.arch.clone())
        .filter(|arch| arch != "unknown")
        .or(file_arch)
        .unwrap_or_else(|| "unknown".to_string());
    let sha1 = sha1_hex_file(&so_path)?;
    Some(IndexEntry {
        id: entry_id,
        path: so_path.to_string_lossy().to_string(),
        build_id: elf_info.and_then(|info| info.build_id),
        sha1,
        arch,
        version,
        info,
        package_url,
        symbol_suffixes,
    })
}

fn version_tuple_for_sort(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect()
}

fn json_string_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| json_string(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_entry(entry: &IndexEntry) -> String {
    let symbol_suffixes = entry
        .symbol_suffixes
        .iter()
        .map(|(key, value)| format!("{}:{}", json_string(key), json_string(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"id\":{},\"path\":{},\"build_id\":{},\"sha1\":{},\"arch\":{},\"version\":{},\"info\":{},\"package_url\":{},\"symbol_suffixes\":{{{}}}}}",
        json_string(&entry.id),
        json_string(&entry.path),
        json_option_string(entry.build_id.as_deref()),
        json_string(&entry.sha1),
        json_string(&entry.arch),
        json_option_string(entry.version.as_deref()),
        json_string(&entry.info),
        json_option_string(entry.package_url.as_deref()),
        symbol_suffixes
    )
}

fn json_map_array(map: &BTreeMap<String, Vec<String>>) -> String {
    map.iter()
        .map(|(key, values)| format!("{}:[{}]", json_string(key), json_string_array(values)))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_nested_map_array(map: &BTreeMap<String, BTreeMap<String, Vec<String>>>) -> String {
    map.iter()
        .map(|(key, inner)| format!("{}:{{{}}}", json_string(key), json_map_array(inner)))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_by_id(map: &BTreeMap<String, usize>) -> String {
    map.iter()
        .map(|(key, value)| format!("{}:{}", json_string(key), value))
        .collect::<Vec<_>>()
        .join(",")
}

fn build_index(args: &[String]) {
    if args.len() != 4 {
        usage();
    }
    let db_path = Path::new(&args[1]);
    let schema_version = args[2].parse::<u32>().unwrap_or(0);
    let common_symbols: Vec<String> = args[3]
        .split(',')
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let Ok(read_dir) = fs::read_dir(db_path) else {
        eprintln!("failed to read db path: {}", db_path.display());
        process::exit(1);
    };
    let mut so_files: Vec<String> = read_dir
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".so"))
        .collect();
    so_files.sort();

    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(1, 8);
    let chunk_size = (so_files.len() + workers - 1) / workers.max(1);
    let mut handles = Vec::new();
    for chunk in so_files.chunks(chunk_size.max(1)) {
        let db_path = db_path.to_path_buf();
        let files = chunk.to_vec();
        let common_symbols = common_symbols.clone();
        handles.push(thread::spawn(move || {
            let mut entries = Vec::new();
            for so_file in files {
                if let Some(entry) = build_index_entry(&db_path, &so_file, &common_symbols) {
                    entries.push(entry);
                }
            }
            entries
        }));
    }

    let mut entries = Vec::new();
    for handle in handles {
        if let Ok(mut worker_entries) = handle.join() {
            entries.append(&mut worker_entries);
        }
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));

    let mut by_id = BTreeMap::new();
    let mut by_arch: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_build_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_build_id_prefix: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_sha1: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_version: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_version_arch: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut by_symbol_suffix: BTreeMap<String, BTreeMap<String, Vec<String>>> = common_symbols
        .iter()
        .map(|symbol| (symbol.clone(), BTreeMap::new()))
        .collect();

    for (index, entry) in entries.iter().enumerate() {
        by_id.insert(entry.id.clone(), index);
        by_arch
            .entry(entry.arch.clone())
            .or_default()
            .push(entry.id.clone());
        by_sha1
            .entry(entry.sha1.clone())
            .or_default()
            .push(entry.id.clone());
        if let Some(build_id) = entry.build_id.as_ref() {
            by_build_id
                .entry(build_id.clone())
                .or_default()
                .push(entry.id.clone());
            by_build_id_prefix
                .entry(build_id.chars().take(16).collect())
                .or_default()
                .push(entry.id.clone());
        }
        if let Some(version) = entry.version.as_ref() {
            by_version
                .entry(version.clone())
                .or_default()
                .push(entry.id.clone());
            by_version_arch
                .entry(version.clone())
                .or_default()
                .entry(entry.arch.clone())
                .or_default()
                .push(entry.id.clone());
        }
        for (symbol, suffix) in &entry.symbol_suffixes {
            by_symbol_suffix
                .entry(symbol.clone())
                .or_default()
                .entry(suffix.clone())
                .or_default()
                .push(entry.id.clone());
        }
    }

    let mut versions_sorted = by_version.keys().cloned().collect::<Vec<_>>();
    versions_sorted.sort_by_key(|version| version_tuple_for_sort(version));
    let entries_json = entries.iter().map(json_entry).collect::<Vec<_>>().join(",");
    println!(
        "{{\"schema_version\":{},\"by_id\":{{{}}},\"by_arch\":{{{}}},\"by_build_id\":{{{}}},\"by_build_id_prefix\":{{{}}},\"by_sha1\":{{{}}},\"by_version\":{{{}}},\"by_version_arch\":{{{}}},\"by_symbol_suffix\":{{{}}},\"versions_sorted\":[{}],\"entries\":[{}]}}",
        schema_version,
        json_by_id(&by_id),
        json_map_array(&by_arch),
        json_map_array(&by_build_id),
        json_map_array(&by_build_id_prefix),
        json_map_array(&by_sha1),
        json_map_array(&by_version),
        json_nested_map_array(&by_version_arch),
        json_nested_map_array(&by_symbol_suffix),
        json_string_array(&versions_sorted),
        entries_json
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(command) = args.get(1).map(String::as_str) else {
        usage();
    };
    match command {
        "extract-abi-tokens" => {
            let input = read_stdin_to_string();
            for token in extract_abi_tokens(&input, &args[2..]) {
                println!("{token}");
            }
        }
        "filter-package-urls" => filter_package_urls(&args[1..]),
        "inspect-elf" => inspect_elf(&args[1..]),
        "build-index" => build_index(&args[1..]),
        _ => usage(),
    }
}
