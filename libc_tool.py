#!/usr/bin/env python3
import os
import re
import json
import gzip
import lzma
import shutil
import sys
import hashlib
import subprocess
import tarfile
import tempfile
import socket
import importlib.util
import urllib.request
import urllib.error
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from functools import partial

ORIGINAL_ARGV = sys.argv[1:]
PWN_IMPORT_ERROR = None
try:
    from pwn import *
except Exception as e:
    PWN_IMPORT_ERROR = e

    class _FallbackContext:
        cache_dir = None
        log_level = 'info'

        @contextmanager
        def local(self, **_kwargs):
            yield self

    class _FallbackLog:
        def _emit(self, level, message):
            sys.stderr.write(f"[{level}] {message}\n")

        def debug(self, message):
            self._emit('*', message)

        def info(self, message):
            self._emit('*', message)

        def warning(self, message):
            self._emit('!', message)

        def error(self, message):
            self._emit('x', message)

        def failure(self, message):
            self._emit('-', message)

        def success(self, message):
            self._emit('+', message)

    class _FallbackText:
        pass

    context = _FallbackContext()
    log = _FallbackLog()
    text = _FallbackText()
    ELF = None
    libcdb = None


LIBC_DB_PATH = "/home/starlight/CtfTools/libc-database/db"
LIBC_INDEX_CACHE = "/home/starlight/CtfTools/libc-database/db/.index_cache.json"
CACHE_SCHEMA_VERSION = 5
INDEX_BUILD_MAX_WORKERS = 8
FILE_ANALYSIS_CACHE = {}
ELF_FAST_INFO_CACHE = {}
COMMON_LIBC_SYMBOLS = [
    '__libc_start_main',
    'system',
    'puts',
    'printf',
    '__isoc99_scanf',
    'read',
    'write',
    'open',
    'execve',
]

MATCH_TYPE_RANK = {
    'exact_sha1': 50,
    'exact': 40,
    'symbol_address': 30,
    'partial': 20,
    'version': 10,
}

UBUNTU_GLIBC_MAP = {
    "16.04": "2.23", "16.10": "2.24", "17.04": "2.25", "17.10": "2.26",
    "18.04": "2.27", "18.10": "2.28", "19.04": "2.29", "19.10": "2.30",
    "20.04": "2.31", "20.10": "2.32", "21.04": "2.33", "21.10": "2.34",
    "22.04": "2.35", "22.10": "2.36", "23.04": "2.37", "23.10": "2.38",
    "24.04": "2.39", "24.10": "2.40", "25.04": "2.41", "25.10": "2.42"
}

UBUNTU_CODENAME_MAP = {
    "16.04": "xenial", "16.10": "yakkety", "17.04": "zesty", "17.10": "artful",
    "18.04": "bionic", "18.10": "cosmic", "19.04": "disco", "19.10": "eoan",
    "20.04": "focal", "20.10": "groovy", "21.04": "hirsute", "21.10": "impish",
    "22.04": "jammy", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic",
    "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing",
}

DEBIAN_GLIBC_MAP = {
    "6": "2.11",
    "7": "2.13",
    "8": "2.19",
    "9": "2.24",
    "10": "2.28",
    "11": "2.31",
    "12": "2.36",
    "13": "2.41",
}

DEBIAN_CODENAME_MAP = {
    "6": "squeeze",
    "7": "wheezy",
    "8": "jessie",
    "9": "stretch",
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
    "squeeze": "squeeze",
    "wheezy": "wheezy",
    "jessie": "jessie",
    "stretch": "stretch",
    "buster": "buster",
    "bullseye": "bullseye",
    "bookworm": "bookworm",
    "trixie": "trixie",
    "forky": "forky",
    "sid": "sid",
    "unstable": "sid",
    "testing": "testing",
}

DEBIAN_CODENAME_SEARCH_ORDER = [
    "trixie",
    "bookworm",
    "bullseye",
    "buster",
    "stretch",
    "jessie",
    "wheezy",
    "squeeze",
    "forky",
    "sid",
    "testing",
]

DEBIAN_GCC_RELEASE_MAP = {
    "14.2.0": "13",
    "12.2.0": "12",
    "10.2.1": "11",
    "10.2.0": "11",
    "8.3.0": "10",
    "6.3.0": "9",
    "4.9.2": "8",
    "4.8.4": "8",
    "4.7.2": "7",
    "4.4.7": "7",
}

SONAME_PACKAGE_HINTS = {
    "libgcc_s.so.1": ["libgcc1", "libgcc-s1"],
    "libstdc++.so.6": ["libstdc++6"],
    "libseccomp.so.2": ["libseccomp2"],
}

ABI_VERSION_PREFIXES_BY_SONAME = {
    "libstdc++.so.6": ("GLIBCXX_", "CXXABI_"),
    "libgcc_s.so.1": ("GCC_",),
}

ABI_VERSION_TOKEN_RE = re.compile(
    r'\b(?:GLIBCXX|CXXABI|GCC)_[0-9][A-Za-z0-9_.]*\b'
    r'|\bGLIBC_(?:[0-9][A-Za-z0-9_.]*|ABI_[A-Za-z0-9_]+)\b'
)
GLIBC_RUNTIME_PREFIXES = ('GLIBC_',)

ANSI_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}

PATCH_BACKUP_SUFFIX = '.bak'
PATCH_SCHEMA_VERSION = 1

def stream_supports_color(stream):
    if os.environ.get("NO_COLOR") is not None:
        return False
    force_color = os.environ.get("FORCE_COLOR")
    if force_color is not None and force_color != "0":
        return True
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        return stream.isatty()
    except Exception:
        return False

def colorize(text, *styles, stream):
    text = str(text)
    styler = getattr(globals().get('text'), "_".join(styles), None)
    if callable(styler):
        return styler(text)
    if not stream_supports_color(stream):
        return text
    prefix = "".join(ANSI_CODES[name] for name in styles if name in ANSI_CODES)
    if not prefix:
        return text
    return f"{prefix}{text}{ANSI_CODES['reset']}"

def stdout_style(text, *styles):
    return colorize(text, *styles, stream=sys.stdout)

def stderr_style(text, *styles):
    return colorize(text, *styles, stream=sys.stderr)

def stdout_heading(text):
    return stdout_style(text, "bold", "blue")

def stdout_number(value):
    return stdout_style(value, "bold", "yellow")

def stdout_path(text):
    return stdout_style(text, "bold", "cyan")

def stdout_ok(text):
    return stdout_style(text, "bold", "green")

def stderr_name(text):
    return stderr_style(text, "bold", "cyan")

def stderr_path(text):
    return stderr_style(text, "bold", "cyan")

def stderr_number(value):
    return stderr_style(value, "bold", "yellow")

def stderr_version(value):
    return stderr_style(value, "bold", "magenta")

def stderr_hash(value):
    return stderr_style(value, "bold", "green")

def stderr_choice(value):
    return stderr_style(value, "bold", "blue")

def stderr_hint(text):
    return stderr_style(text, "bold", "green")

def ensure_pwntools_cache_dir():
    if context.cache_dir:
        return context.cache_dir
    cache_bases = [
        os.environ.get("XDG_CACHE_HOME"),
        '/tmp',
        os.path.join(os.getcwd(), '.cache'),
        os.path.join(os.path.expanduser("~"), ".cache"),
    ]
    cache_suffix = f".pwntools-cache-{sys.version_info.major}.{sys.version_info.minor}"
    for base in cache_bases:
        if not base:
            continue
        cache_dir = os.path.join(base, cache_suffix)
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            continue
        if not os.access(cache_dir, os.W_OK):
            continue
        context.cache_dir = cache_dir
        if context.cache_dir:
            return context.cache_dir
    return None

def find_rust_core_binary():
    candidates = []
    env_path = os.environ.get("LIBC_TOOL_CORE")
    if env_path:
        candidates.append(env_path)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.extend([
        os.path.join(script_dir, 'libc_tool_core'),
        os.path.join(script_dir, 'target', 'release', 'libc_tool_core'),
        os.path.join(os.getcwd(), 'target', 'release', 'libc_tool_core'),
    ])
    path_candidate = shutil.which('libc_tool_core')
    if path_candidate:
        candidates.append(path_candidate)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

def run_rust_core(args, input_text, timeout=10):
    core_path = find_rust_core_binary()
    if not core_path:
        return None
    try:
        result = subprocess.run(
            [core_path] + list(args),
            input=input_text or '',
            capture_output=True,
            text=True,
            timeout=timeout,
            env=readelf_env(),
        )
    except Exception as e:
        log.debug(f"Rust core 执行失败: {e}")
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        log.debug(f"Rust core 返回失败: {detail}")
        return None
    return result.stdout

def inspect_elf_fast(elf_path):
    abs_path = os.path.abspath(elf_path)
    try:
        stat_result = os.stat(abs_path)
    except OSError:
        return None
    cache_key = (abs_path, stat_result.st_mtime_ns, stat_result.st_size)
    cached = ELF_FAST_INFO_CACHE.get(cache_key)
    if cached is not None:
        return cached
    core_output = run_rust_core(['inspect-elf', abs_path], '', timeout=5)
    if core_output is None:
        return None
    try:
        info = json.loads(core_output)
    except json.JSONDecodeError as e:
        log.debug(f"Rust core ELF JSON 解析失败: {e}")
        return None
    if not isinstance(info, dict):
        return None
    info.setdefault('build_id', None)
    info.setdefault('arch', 'unknown')
    info.setdefault('has_dynamic', False)
    info.setdefault('has_debug', False)
    info.setdefault('needed', [])
    ELF_FAST_INFO_CACHE[cache_key] = info
    return info

def libc_tool_cache_targets():
    targets = []
    cache_dir = ensure_pwntools_cache_dir()
    if cache_dir:
        for name in ('libc_tool_extra_libs', 'libcdb_libs', 'libcdb_dbg', 'libcdb'):
            targets.append(os.path.join(cache_dir, name))
    targets.append(LIBC_INDEX_CACHE)
    return list(dict.fromkeys(targets))

def path_size(path):
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path) or os.path.islink(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                total += os.path.getsize(file_path)
            except OSError:
                pass
    return total

def format_bytes(size):
    value = float(size)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024 or unit == 'GB':
            if unit == 'B':
                return f"{int(value)}{unit}"
            return f"{value:.2f}{unit}"
        value /= 1024
    return f"{value:.2f}GB"

def clear_libc_tool_cache():
    removed = []
    skipped = []
    total_size = 0
    for target in libc_tool_cache_targets():
        if not os.path.exists(target):
            skipped.append(target)
            continue
        size = path_size(target)
        try:
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target)
            else:
                os.unlink(target)
        except OSError as e:
            log.warning(f"清理缓存失败: {stderr_path(target)} ({e})")
            continue
        total_size += size
        removed.append((target, size))
    return {
        'removed': removed,
        'skipped': skipped,
        'bytes': total_size,
    }

def readelf_env():
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env

def is_libc_family_name(name):
    basename = os.path.basename(name).lower()
    return (
        basename.startswith("libc")
        or basename in {"ld.so", "ld-linux.so.2", "ld-linux-x86-64.so.2"}
        or re.fullmatch(r"ld-\d+(?:\.\d+)*\.so", basename) is not None
    )

def is_shared_object_artifact(name):
    basename = os.path.basename(name)
    return (
        re.search(r"\.so(?:\.[^/]+)*$", basename) is not None
        or basename.startswith("ld-linux")
        or re.fullmatch(r"ld-\d+(?:\.\d+)*\.so", basename) is not None
    )

def guess_package_names_from_soname(soname):
    candidates = list(SONAME_PACKAGE_HINTS.get(soname, ()))
    match = re.match(r"^(lib[^/]+)\.so(?:\.([0-9][^/]*))?$", soname)
    if match:
        stem, abi = match.groups()
        normalized = stem.replace("_", "-")
        if abi:
            candidates.extend([
                f"{normalized}{abi}",
                f"{normalized}-{abi}",
            ])
        candidates.append(normalized)
    deduped = []
    seen = set()
    for item in candidates:
        if item and item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped

def normalize_soname_list(items):
    normalized = []
    seen = set()
    for item in items or ():
        soname = (item or '').strip()
        if not soname:
            continue
        if '.so' not in soname:
            raise ValueError(f"无效的 soname: {item}")
        if soname not in seen:
            normalized.append(soname)
            seen.add(soname)
    return normalized

def parse_package_hint_specs(specs):
    hints = {}
    for raw_spec in specs or ():
        spec = (raw_spec or '').strip()
        if not spec:
            continue
        if '=' not in spec:
            raise ValueError(f"无效的 --package-hint，期望 SONAME=PKG1,PKG2: {raw_spec}")
        soname, package_blob = spec.split('=', 1)
        soname = soname.strip()
        if not soname or '.so' not in soname:
            raise ValueError(f"无效的 --package-hint soname: {raw_spec}")
        packages = []
        for package_name in package_blob.split(','):
            package_name = package_name.strip()
            if not package_name:
                continue
            packages.append(package_name)
        if not packages:
            raise ValueError(f"无效的 --package-hint 包名列表: {raw_spec}")
        target = hints.setdefault(soname, [])
        for package_name in packages:
            if package_name not in target:
                target.append(package_name)
    return hints

def normalize_package_name_list(items):
    normalized = []
    seen = set()
    for item in items or ():
        for raw_name in str(item).split(','):
            package_name = raw_name.strip()
            if not package_name:
                continue
            if not re.fullmatch(r"[A-Za-z0-9.+-]+", package_name):
                raise ValueError(f"无效的包名: {package_name}")
            if package_name not in seen:
                normalized.append(package_name)
                seen.add(package_name)
    return normalized

def guess_package_names_from_soname_with_hints(soname, package_hints=None):
    candidates = []
    for item in (package_hints or {}).get(soname, ()):
        if item not in candidates:
            candidates.append(item)
    for item in guess_package_names_from_soname(soname):
        if item not in candidates:
            candidates.append(item)
    return candidates

def get_needed_shared_libraries(elf_path):
    fast_info = inspect_elf_fast(elf_path)
    if fast_info is not None and fast_info.get('needed'):
        return list(dict.fromkeys(fast_info.get('needed') or []))
    try:
        result = subprocess.run(
            ['readelf', '-d', elf_path],
            capture_output=True,
            text=True,
            check=False,
            env=readelf_env(),
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    needed = re.findall(r"Shared library:\s+\[(.+?)\]", result.stdout)
    return list(dict.fromkeys(needed))

def get_requested_shared_libraries(elf_path=None, extra_needed=None):
    requested = []
    seen = set()
    if elf_path and os.path.exists(elf_path):
        for soname in get_needed_shared_libraries(elf_path):
            if soname not in seen:
                requested.append(soname)
                seen.add(soname)
    for soname in normalize_soname_list(extra_needed):
        if soname not in seen:
            requested.append(soname)
            seen.add(soname)
    return requested

def find_associated_elf_for_libc(libc_path):
    parent_dir = os.path.dirname(os.path.abspath(libc_path))
    if not parent_dir or not os.path.isdir(parent_dir):
        return None
    candidates = []
    for entry in sorted(os.listdir(parent_dir)):
        entry_path = os.path.join(parent_dir, entry)
        if not os.path.isfile(entry_path):
            continue
        if os.path.abspath(entry_path) == os.path.abspath(libc_path):
            continue
        if is_libc_family_name(entry):
            continue
        if not is_elf_file(entry_path):
            continue
        needed = get_needed_shared_libraries(entry_path)
        if 'libc.so.6' in needed:
            candidates.append(entry_path)
    if len(candidates) == 1:
        log.info(f"自动关联 ELF: {stderr_path(candidates[0])}")
        return candidates[0]
    if len(candidates) > 1:
        preferred = [path for path in candidates if os.access(path, os.X_OK)]
        if len(preferred) == 1:
            log.info(f"自动关联 ELF: {stderr_path(preferred[0])}")
            return preferred[0]
        log.warning("同目录存在多个 ELF，跳过额外依赖自动补全")
    return None

def resolve_reference_elf(input_path):
    if not input_path or not os.path.exists(input_path):
        return None
    if is_elf_file(input_path) and not is_libc_family_name(input_path):
        return input_path
    return find_associated_elf_for_libc(input_path)

def resolve_reference_elf_arg(input_path, explicit_elf=None):
    if explicit_elf:
        return os.path.abspath(explicit_elf)
    return resolve_reference_elf(input_path)

def list_default_libc_candidates(search_dir):
    if not search_dir or not os.path.isdir(search_dir):
        return []
    candidates = []
    for entry in sorted(os.listdir(search_dir)):
        entry_path = os.path.join(search_dir, entry)
        if not os.path.isfile(entry_path):
            continue
        if not is_libc_family_name(entry):
            continue
        if not is_elf_file(entry_path):
            continue
        candidates.append(entry_path)
    return candidates

def choose_default_libc_candidate(candidates):
    if not candidates:
        return None

    versioned = [
        path for path in candidates
        if re.fullmatch(r"libc-\d+(?:\.\d+)*\.so", os.path.basename(path)) is not None
    ]
    if len(versioned) == 1:
        return versioned[0]
    if len(versioned) > 1:
        return None

    canonical = [
        path for path in candidates
        if os.path.basename(path) == 'libc.so.6'
    ]
    if len(canonical) == 1:
        return canonical[0]
    if len(canonical) > 1:
        return None

    libc_named = [
        path for path in candidates
        if os.path.basename(path).startswith('libc')
    ]
    if len(libc_named) == 1:
        return libc_named[0]
    if len(candidates) == 1:
        return candidates[0]
    return None

def auto_resolve_input_file(input_path=None, reference_elf=None):
    if input_path:
        return os.path.abspath(input_path), []
    search_dir = (
        os.path.dirname(os.path.abspath(reference_elf))
        if reference_elf else
        os.getcwd()
    )
    candidates = list_default_libc_candidates(search_dir)
    selected = choose_default_libc_candidate(candidates)
    return selected, candidates

def get_download_target_dir(input_path, reference_elf=None):
    preferred_path = reference_elf or input_path
    if preferred_path:
        base_dir = os.path.dirname(os.path.abspath(preferred_path))
    else:
        base_dir = os.getcwd()
    return os.path.join(base_dir, 'libc_dir')

def get_directory_entry_names(target_dir):
    try:
        return {entry.name for entry in os.scandir(target_dir)}
    except FileNotFoundError:
        return set()
    except NotADirectoryError:
        return set()

def has_named_artifact(target_dir, name):
    return name in get_directory_entry_names(target_dir)

def abi_version_prefixes_for_soname(soname):
    return ABI_VERSION_PREFIXES_BY_SONAME.get(soname, ())

def abi_version_sort_key(token):
    prefix, _sep, version = str(token).partition('_')
    parts = []
    for part in re.findall(r'\d+|[A-Za-z]+|[^A-Za-z\d]+', version):
        if part.isdigit():
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return prefix, tuple(parts)

def extract_abi_version_tokens(text_value, prefixes=None):
    prefixes = tuple(prefixes or ())
    core_output = run_rust_core(['extract-abi-tokens'] + list(prefixes), text_value or '')
    if core_output is not None:
        return {line.strip() for line in core_output.splitlines() if line.strip()}
    tokens = set(ABI_VERSION_TOKEN_RE.findall(text_value or ''))
    if prefixes:
        tokens = {token for token in tokens if token.startswith(prefixes)}
    return tokens

def parse_version_needs_by_file(readelf_version_output):
    needs = {}
    current_file = None
    for line in (readelf_version_output or '').splitlines():
        file_match = re.search(r'\bFile:\s+(\S+)', line)
        if file_match:
            current_file = file_match.group(1)
            needs.setdefault(current_file, set())
        if not current_file:
            continue
        for token in extract_abi_version_tokens(line):
            needs.setdefault(current_file, set()).add(token)
    return needs

def get_required_abi_versions_by_soname(elf_path):
    if not elf_path or not os.path.exists(elf_path):
        return {}
    analysis = cached_file_analysis(elf_path)
    needs_by_file = parse_version_needs_by_file(analysis.get('readelf_version', ''))
    result = {}
    fallback_text = "\n".join((
        analysis.get('readelf_version', ''),
        analysis.get('objdump_t', ''),
    ))
    for soname, prefixes in ABI_VERSION_PREFIXES_BY_SONAME.items():
        required = set()
        for needed_file, tokens in needs_by_file.items():
            if needed_file == soname:
                required.update(token for token in tokens if token.startswith(prefixes))
        if not required:
            required.update(extract_abi_version_tokens(fallback_text, prefixes=prefixes))
        if required:
            result[soname] = required
    return result

def get_required_abi_versions_for_soname(elf_path, soname):
    prefixes = abi_version_prefixes_for_soname(soname)
    if not prefixes:
        return set()
    return set(get_required_abi_versions_by_soname(elf_path).get(soname, set()))

def get_provided_abi_versions(library_path, soname=None):
    prefixes = abi_version_prefixes_for_soname(soname) if soname else None
    if not library_path or not os.path.exists(library_path):
        return set()
    analysis = cached_file_analysis(library_path)
    text_value = "\n".join((
        analysis.get('readelf_version', ''),
        analysis.get('strings', ''),
        analysis.get('objdump_t', ''),
    ))
    return extract_abi_version_tokens(text_value, prefixes=prefixes)

def get_required_versions_from_needed_file(elf_path, needed_file, prefixes=None):
    if not elf_path or not os.path.exists(elf_path):
        return set()
    needs_by_file = parse_version_needs_by_file(
        cached_file_analysis(elf_path).get('readelf_version', '')
    )
    return extract_abi_version_tokens(
        "\n".join(sorted(needs_by_file.get(needed_file, set()))),
        prefixes=prefixes,
    )

def get_required_libc_runtime_versions(library_path):
    return get_required_versions_from_needed_file(
        library_path,
        'libc.so.6',
        prefixes=GLIBC_RUNTIME_PREFIXES,
    )

def get_provided_libc_runtime_versions(libc_path):
    if not libc_path or not os.path.exists(libc_path):
        return set()
    analysis = cached_file_analysis(libc_path)
    provided = set()
    provided.update(extract_abi_version_tokens(
        analysis.get('strings', ''),
        prefixes=GLIBC_RUNTIME_PREFIXES,
    ))
    provided.update(extract_abi_version_tokens(
        analysis.get('readelf_version', ''),
        prefixes=GLIBC_RUNTIME_PREFIXES,
    ))
    provided.update(extract_abi_version_tokens(
        analysis.get('objdump_t', ''),
        prefixes=GLIBC_RUNTIME_PREFIXES,
    ))
    return provided

def check_library_libc_runtime_compatibility(library_path, runtime_libc_path):
    if not library_path or not os.path.exists(library_path):
        return {
            'ok': False,
            'reason': 'missing',
            'required': set(),
            'provided': set(),
            'missing': set(),
        }
    if not runtime_libc_path or not os.path.exists(runtime_libc_path):
        return {
            'ok': False,
            'reason': 'runtime_libc_missing',
            'required': set(),
            'provided': set(),
            'missing': set(),
        }
    required = get_required_libc_runtime_versions(library_path)
    if not required:
        return {
            'ok': True,
            'reason': 'no_runtime_version_requirement',
            'required': required,
            'provided': set(),
            'missing': set(),
        }
    provided = get_provided_libc_runtime_versions(runtime_libc_path)
    missing = required - provided
    return {
        'ok': not missing,
        'reason': 'ok' if not missing else 'missing_runtime_versions',
        'required': required,
        'provided': provided,
        'missing': missing,
    }

def summarize_abi_versions(tokens, limit=4):
    ordered = sorted(tokens or (), key=abi_version_sort_key)
    if not ordered:
        return '-'
    if len(ordered) <= limit:
        return ', '.join(ordered)
    head = ', '.join(ordered[:limit])
    return f"{head}, ... ({len(ordered)} 个)"

def find_library_artifact(root_dir, soname, require_dynamic=False):
    if not root_dir or not soname or not os.path.isdir(root_dir):
        return None
    candidates = []
    for root, _dirs, files in os.walk(root_dir):
        for file_name in sorted(files):
            if file_name == soname:
                priority = 0
            elif file_name.startswith(soname + '.'):
                priority = 1
            else:
                continue
            candidate = os.path.join(root, file_name)
            if not os.path.isfile(candidate):
                continue
            if require_dynamic and is_elf_file(candidate) and not elf_has_dynamic_section(candidate):
                continue
            candidates.append((priority, len(file_name), candidate))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][2]

def check_library_abi_satisfaction(library_path, soname, required_versions=None):
    required = set(required_versions or ())
    if not library_path or not os.path.exists(library_path):
        return {
            'ok': False,
            'reason': 'missing',
            'required': required,
            'provided': set(),
            'missing': required,
        }
    if is_elf_file(library_path) and not elf_has_dynamic_section(library_path):
        return {
            'ok': False,
            'reason': 'no_dynamic_section',
            'required': required,
            'provided': set(),
            'missing': required,
        }
    if not required:
        return {
            'ok': True,
            'reason': 'no_version_requirement',
            'required': required,
            'provided': set(),
            'missing': set(),
        }
    provided = get_provided_abi_versions(library_path, soname=soname)
    missing = required - provided
    return {
        'ok': not missing,
        'reason': 'ok' if not missing else 'missing_versions',
        'required': required,
        'provided': provided,
        'missing': missing,
    }

def library_satisfies_abi_requirements(library_path, soname, elf_path=None, required_versions=None):
    if required_versions is None:
        required_versions = get_required_abi_versions_for_soname(elf_path, soname)
    return check_library_abi_satisfaction(library_path, soname, required_versions=required_versions)

def library_satisfies_runtime_libc(library_path, runtime_libc_path):
    return check_library_libc_runtime_compatibility(library_path, runtime_libc_path)

def get_missing_needed_libraries(elf_path, target_dir, extra_needed=None):
    missing = []
    present_names = get_directory_entry_names(target_dir)
    required_versions_by_soname = get_required_abi_versions_by_soname(elf_path)
    runtime_libc_path = find_library_artifact(target_dir, 'libc.so.6', require_dynamic=True)
    for soname in get_requested_shared_libraries(elf_path, extra_needed=extra_needed):
        if soname == 'libc.so.6':
            continue
        if soname in present_names:
            library_path = find_library_artifact(target_dir, soname)
            status = library_satisfies_abi_requirements(
                library_path,
                soname,
                required_versions=required_versions_by_soname.get(soname, set()),
            )
            if status['ok']:
                runtime_status = library_satisfies_runtime_libc(library_path, runtime_libc_path)
                if runtime_status['ok']:
                    continue
            missing.append(soname)
            continue
        missing.append(soname)
    return missing

def find_nearest_existing_parent(path):
    current = os.path.abspath(path)
    while not os.path.exists(current):
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
    return current

def module_check(name):
    try:
        spec = importlib.util.find_spec(name)
    except Exception:
        spec = None
    if spec is None:
        return False, None
    return True, spec.origin

def command_check(name):
    path = shutil.which(name)
    return bool(path), path

def require_command(name, feature=None):
    ok, path = command_check(name)
    if ok:
        return path
    feature_text = f" for {feature}" if feature else ""
    raise RuntimeError(f"missing required command{feature_text}: {name}")

def loader_name_candidates_for_arch(arch):
    arch = normalize_arch_name(arch)
    if arch == 'amd64':
        return ['ld-linux-x86-64.so.2', 'ld-linux.so.2']
    if arch == 'i386':
        return ['ld-linux.so.2']
    if arch == 'aarch64':
        return ['ld-linux-aarch64.so.1']
    if arch == 'arm':
        return ['ld-linux-armhf.so.3', 'ld-linux.so.3']
    if arch == 'x32':
        return ['ld-linux-x32.so.2', 'ld-linux-x86-64.so.2']
    return []

def is_loader_artifact_name(name):
    basename = os.path.basename(name)
    return (
        basename == 'ld.so'
        or basename.startswith('ld-linux')
        or re.fullmatch(r'ld-\d+(?:\.\d+)*\.so(?:\.[^/]+)*', basename) is not None
    )

def iter_patchable_shared_objects(target_dir):
    if not target_dir or not os.path.isdir(target_dir):
        return []
    patchable = []
    seen = set()
    for root, _dirs, files in os.walk(target_dir):
        for file_name in sorted(files):
            if not is_shared_object_artifact(file_name):
                continue
            if is_loader_artifact_name(file_name):
                continue
            file_path = os.path.join(root, file_name)
            if file_path in seen or not os.path.isfile(file_path):
                continue
            if not is_elf_file(file_path) or not elf_has_dynamic_section(file_path):
                continue
            patchable.append(file_path)
            seen.add(file_path)
    return patchable

def resolve_runtime_loader(target_dir, elf_path):
    if not target_dir or not os.path.isdir(target_dir):
        return None
    arch = get_elf_arch(elf_path)
    for loader_name in loader_name_candidates_for_arch(arch):
        loader_path = find_library_artifact(target_dir, loader_name, require_dynamic=True)
        if loader_path:
            return loader_path
    fallback = []
    for root, _dirs, files in os.walk(target_dir):
        for file_name in sorted(files):
            if not is_loader_artifact_name(file_name):
                continue
            file_path = os.path.join(root, file_name)
            if not os.path.isfile(file_path):
                continue
            if is_elf_file(file_path) and not elf_has_dynamic_section(file_path):
                continue
            fallback.append(file_path)
    return sorted(fallback)[0] if fallback else None

def origin_relative_path(from_dir, to_path):
    rel_path = os.path.relpath(os.path.abspath(to_path), os.path.abspath(from_dir))
    rel_path = rel_path.replace(os.sep, '/')
    if rel_path == '.':
        return '$ORIGIN'
    return f"$ORIGIN/{rel_path}"

def compute_main_rpath(elf_path, target_dir):
    elf_dir = os.path.dirname(os.path.abspath(elf_path))
    entries = [origin_relative_path(elf_dir, target_dir), '$ORIGIN']
    deduped = []
    for entry in entries:
        if entry not in deduped:
            deduped.append(entry)
    return ':'.join(deduped)

def format_patch_transition(before, after, formatter=None, missing='-'):
    formatter = formatter or (lambda value: value)
    before_text = missing if before in (None, '') else before
    after_text = missing if after in (None, '') else after
    return f"{formatter(before_text)} -> {formatter(after_text)}"

def get_patch_backup_path(elf_path):
    return os.path.abspath(elf_path) + PATCH_BACKUP_SUFFIX

def sha256_of_file(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def get_program_interpreter(elf_path):
    if not elf_path or not os.path.exists(elf_path) or not is_elf_file(elf_path):
        return None
    try:
        result = subprocess.run(
            ['readelf', '-l', elf_path],
            capture_output=True,
            text=True,
            check=False,
            env=readelf_env(),
        )
    except Exception:
        return None
    output = (result.stdout or '') + (result.stderr or '')
    match = re.search(r'Requesting program interpreter:\s*([^\]]+)', output)
    if not match:
        return None
    return match.group(1).strip()

def get_dynamic_search_paths(elf_path):
    result = {
        'rpath': None,
        'runpath': None,
        'effective': None,
    }
    if not elf_path or not os.path.exists(elf_path) or not is_elf_file(elf_path):
        return result
    try:
        proc = subprocess.run(
            ['readelf', '-d', elf_path],
            capture_output=True,
            text=True,
            check=False,
            env=readelf_env(),
        )
    except Exception:
        return result
    output = (proc.stdout or '') + (proc.stderr or '')
    runpath_match = re.search(r'\(RUNPATH\).*Library runpath: \[(.*?)\]', output)
    rpath_match = re.search(r'\(RPATH\).*Library rpath: \[(.*?)\]', output)
    if rpath_match:
        result['rpath'] = rpath_match.group(1)
    if runpath_match:
        result['runpath'] = runpath_match.group(1)
    result['effective'] = result['runpath'] or result['rpath']
    return result

def snapshot_patch_target_state(elf_path):
    paths = get_dynamic_search_paths(elf_path)
    return {
        'path': os.path.abspath(elf_path),
        'sha256': sha256_of_file(elf_path),
        'build_id': build_id_from_elf(elf_path),
        'interpreter': get_program_interpreter(elf_path),
        'rpath': paths.get('rpath'),
        'runpath': paths.get('runpath'),
        'effective_rpath': paths.get('effective'),
    }

def backup_patch_target(elf_path):
    elf_path = os.path.abspath(elf_path)
    backup_path = get_patch_backup_path(elf_path)
    if os.path.exists(backup_path):
        log.info(f"复用已有 patch 备份: {stderr_path(backup_path)}")
        return backup_path
    shutil.copy2(elf_path, backup_path)
    log.info(f"创建 patch 备份: {stderr_path(backup_path)}")
    return backup_path

def restore_patched_elf(elf_path):
    elf_path = os.path.abspath(elf_path)
    backup_path = get_patch_backup_path(elf_path)
    if not os.path.exists(backup_path):
        raise RuntimeError(f"patch backup not found: {backup_path}")
    fd, tmp_path = tempfile.mkstemp(
        prefix=os.path.basename(elf_path) + '.restore.',
        suffix='.tmp',
        dir=os.path.dirname(elf_path),
    )
    os.close(fd)
    try:
        shutil.copy2(backup_path, tmp_path)
        os.replace(tmp_path, elf_path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    os.unlink(backup_path)
    return elf_path

def build_patch_plan(elf_path, target_dir, mode='rpath', extra_needed=None):
    elf_path = os.path.abspath(elf_path)
    target_dir = os.path.abspath(target_dir)
    if mode not in ('rpath', 'replace-needed'):
        raise RuntimeError(f"unsupported patch mode: {mode}")
    if not os.path.exists(elf_path):
        raise RuntimeError(f"ELF not found: {elf_path}")
    if not is_elf_file(elf_path):
        raise RuntimeError(f"target is not an ELF: {elf_path}")
    if not os.path.isdir(target_dir):
        raise RuntimeError(f"runtime directory not found: {target_dir}")
    loader_path = resolve_runtime_loader(target_dir, elf_path)
    if not loader_path:
        raise RuntimeError(f"runtime loader not found in {target_dir}")
    missing = get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed)
    if missing:
        raise RuntimeError(
            "runtime directory still misses required libraries: " + ", ".join(sorted(missing))
        )
    replace_needed = []
    if mode == 'replace-needed':
        for soname in get_needed_shared_libraries(elf_path):
            if is_loader_artifact_name(soname):
                continue
            resolved = find_library_artifact(target_dir, soname, require_dynamic=True)
            if resolved:
                replace_needed.append((soname, resolved))
    source_libc = find_library_artifact(target_dir, 'libc.so.6', require_dynamic=True)
    if not source_libc:
        raise RuntimeError(f"runtime libc not found in {target_dir}")
    return {
        'schema_version': PATCH_SCHEMA_VERSION,
        'elf_path': elf_path,
        'target_dir': target_dir,
        'mode': mode,
        'loader_path': loader_path,
        'main_rpath': compute_main_rpath(elf_path, target_dir),
        'library_rpath': '$ORIGIN',
        'replace_needed': replace_needed,
        'patch_libraries': iter_patchable_shared_objects(target_dir),
        'backup_path': get_patch_backup_path(elf_path),
        'source_libc': source_libc,
        'source_build_id': build_id_from_elf(source_libc),
        'source_sha256': sha256_of_file(source_libc),
    }

def files_share_identity(path_a, path_b):
    if not path_a or not path_b:
        return False
    try:
        return os.path.samefile(path_a, path_b)
    except OSError:
        return os.path.abspath(path_a) == os.path.abspath(path_b)

def inspect_runtime_dir_for_patch(target_dir, elf_path, extra_needed=None):
    target_dir = os.path.abspath(target_dir)
    result = {
        'ok': False,
        'reason': None,
        'target_dir': target_dir,
        'runtime_libc': None,
        'loader_path': None,
        'missing_libraries': [],
    }
    if not os.path.isdir(target_dir):
        result['reason'] = 'dir_missing'
        return result
    runtime_libc = find_library_artifact(target_dir, 'libc.so.6', require_dynamic=True)
    if not runtime_libc:
        result['reason'] = 'libc_missing'
        return result
    result['runtime_libc'] = runtime_libc
    loader_path = resolve_runtime_loader(target_dir, elf_path)
    if not loader_path:
        result['reason'] = 'loader_missing'
        return result
    result['loader_path'] = loader_path
    missing_libraries = get_missing_needed_libraries(
        elf_path,
        target_dir,
        extra_needed=extra_needed,
    )
    if missing_libraries:
        result['reason'] = 'libraries_missing'
        result['missing_libraries'] = sorted(missing_libraries)
        return result
    result['ok'] = True
    result['reason'] = 'ok'
    return result

def inspect_local_runtime_dir_for_libc(libc_path, elf_path, extra_needed=None):
    libc_path = os.path.abspath(libc_path)
    result = inspect_runtime_dir_for_patch(
        os.path.dirname(libc_path),
        elf_path,
        extra_needed=extra_needed,
    )
    result['provided_libc_path'] = libc_path
    runtime_libc = result.get('runtime_libc')
    if runtime_libc and not files_share_identity(runtime_libc, libc_path):
        result['ok'] = False
        result['reason'] = 'libc_mismatch'
    return result

def format_runtime_probe_failure(result):
    reason = (result or {}).get('reason')
    if reason == 'dir_missing':
        return '运行库目录不存在'
    if reason == 'libc_missing':
        return '同目录未找到可用的 libc.so.6'
    if reason == 'loader_missing':
        return '同目录未找到匹配的 loader'
    if reason == 'libraries_missing':
        missing = ', '.join((result or {}).get('missing_libraries') or ())
        return f"同目录仍缺少依赖: {missing}"
    if reason == 'libc_mismatch':
        return '给定 libc 与目录内实际用于 patch 的 libc.so.6 不一致'
    return '本地运行库不完整'

def run_patchelf(args):
    require_command('patchelf', feature='patching ELF')
    try:
        result = subprocess.run(
            ['patchelf'] + list(args),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        raise RuntimeError(f"failed to execute patchelf: {e}") from e
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(f"patchelf {' '.join(args)} failed: {detail or 'unknown error'}")
    return result.stdout

def apply_patch_plan(plan):
    for library_path in plan.get('patch_libraries', ()):
        run_patchelf(['--force-rpath', '--set-rpath', plan['library_rpath'], library_path])
    main_path = plan.get('staged_elf_path', plan['elf_path'])
    run_patchelf(['--set-interpreter', plan['loader_path'], main_path])
    if plan['mode'] == 'rpath':
        run_patchelf(['--force-rpath', '--set-rpath', plan['main_rpath'], main_path])
    else:
        for soname, resolved_path in plan.get('replace_needed', ()):
            run_patchelf(['--replace-needed', soname, resolved_path, main_path])
    return main_path

def verify_patch_plan(plan):
    main_path = plan.get('staged_elf_path', plan['elf_path'])
    loader_path = plan['loader_path']
    library_path = ':'.join([
        plan['target_dir'],
        os.path.dirname(main_path),
    ])
    result = subprocess.run(
        [loader_path, '--library-path', library_path, '--list', main_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(f"loader verification failed: {detail or 'unknown error'}")
    return result.stdout

def patch_elf_with_runtime_dir(elf_path, target_dir, mode='rpath', verify=True, extra_needed=None):
    elf_path = os.path.abspath(elf_path)
    plan = build_patch_plan(elf_path, target_dir, mode=mode, extra_needed=extra_needed)
    backup_path = backup_patch_target(elf_path)
    original_state = snapshot_patch_target_state(backup_path)
    fd, staged_path = tempfile.mkstemp(
        prefix=os.path.basename(elf_path) + '.patch.',
        suffix='.tmp',
        dir=os.path.dirname(elf_path),
    )
    os.close(fd)
    try:
        shutil.copy2(backup_path, staged_path)
        plan['staged_elf_path'] = staged_path
        apply_patch_plan(plan)
        if verify:
            verify_patch_plan(plan)
        os.replace(staged_path, elf_path)
    finally:
        if os.path.exists(staged_path):
            os.unlink(staged_path)
    patched_state = snapshot_patch_target_state(elf_path)
    plan['original_state'] = original_state
    plan['patched_state'] = patched_state
    return plan

def tcp_probe(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port}"
    except Exception as e:
        return False, str(e)

def append_doctor_check(checks, name, status, detail, required=True):
    checks.append({
        'name': name,
        'status': status,
        'detail': detail,
        'required': required,
    })

def run_doctor():
    checks = []

    append_doctor_check(
        checks,
        'python_version',
        'ok',
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    append_doctor_check(
        checks,
        'locale',
        'ok',
        f"LANG={os.environ.get('LANG', '') or '-'} LC_ALL={os.environ.get('LC_ALL', '') or '-'} readelf=LC_ALL=C",
    )

    pwn_ok = PWN_IMPORT_ERROR is None
    append_doctor_check(
        checks,
        'python_module:pwn',
        'ok' if pwn_ok else 'error',
        'pwntools 已加载' if pwn_ok else f'缺少 pwntools: {PWN_IMPORT_ERROR}',
    )
    for module_name, required in [('unix_ar', False), ('zstandard', False)]:
        ok, origin = module_check(module_name)
        append_doctor_check(
            checks,
            f'python_module:{module_name}',
            'ok' if ok else 'warning',
            origin or '未安装',
            required=required,
        )

    for cmd in ('readelf', 'objdump', 'strings'):
        ok, path = command_check(cmd)
        append_doctor_check(
            checks,
            f'command:{cmd}',
            'ok' if ok else 'error',
            path or '未找到',
        )
    ok, path = command_check('patchelf')
    append_doctor_check(
        checks,
        'command:patchelf',
        'ok' if ok else 'warning',
        path or '未找到（仅 --patch/--restore 需要）',
        required=False,
    )

    db_exists = os.path.isdir(LIBC_DB_PATH)
    db_entries = 0
    if db_exists:
        try:
            db_entries = sum(
                1 for name in os.listdir(LIBC_DB_PATH)
                if name.endswith(('.so', '.symbols', '.info'))
            )
        except OSError:
            db_entries = 0
    append_doctor_check(
        checks,
        'libc_db',
        'ok' if db_exists else 'error',
        f"{LIBC_DB_PATH} ({db_entries} files)" if db_exists else f"不存在: {LIBC_DB_PATH}",
    )
    append_doctor_check(
        checks,
        'index_cache',
        'ok' if os.path.exists(LIBC_INDEX_CACHE) else 'warning',
        LIBC_INDEX_CACHE if os.path.exists(LIBC_INDEX_CACHE) else f"缺失: {LIBC_INDEX_CACHE}",
        required=False,
    )

    cache_dir = ensure_pwntools_cache_dir()
    append_doctor_check(
        checks,
        'cache_dir',
        'ok' if cache_dir else 'error',
        cache_dir or '无法创建可写缓存目录',
    )

    for name, host, port, required in (
        ('network:launchpad', 'launchpad.net', 443, False),
        ('network:archive_ubuntu', 'archive.ubuntu.com', 80, True),
        ('network:security_ubuntu', 'security.ubuntu.com', 80, False),
        ('network:old_releases_ubuntu', 'old-releases.ubuntu.com', 80, False),
        ('network:debian', 'deb.debian.org', 443, False),
        ('network:security_debian', 'security.debian.org', 443, False),
        ('network:archive_debian', 'archive.debian.org', 443, False),
        ('network:libc_rip', 'libc.rip', 443, False),
    ):
        ok, detail = tcp_probe(host, port)
        append_doctor_check(
            checks,
            name,
            'ok' if ok else ('error' if required else 'warning'),
            detail,
            required=required,
        )

    has_error = any(item['status'] == 'error' and item['required'] for item in checks)
    return {
        'ok': not has_error,
        'mode': 'doctor',
        'checks': checks,
    }

def print_doctor_report(report):
    status_to_logger = {
        'ok': log.success,
        'warning': log.warning,
        'error': log.failure,
    }
    log.info("开始环境自检...")
    for item in report['checks']:
        status_to_logger.get(item['status'], log.info)(
            f"{item['name']}: {item['detail']}"
        )
    if report['ok']:
        log.success("环境自检通过")
    else:
        log.failure("环境自检未通过")

def get_ubuntu_glibc_package_version(libc_path):
    strings_output = cached_file_analysis(libc_path).get('strings', '')
    match = re.search(r"GNU C Library \(Ubuntu E?GLIBC ([^)]+)\)", strings_output)
    if match:
        return match.group(1)
    return None

def get_debian_glibc_package_version(libc_path):
    strings_output = cached_file_analysis(libc_path).get('strings', '')
    match = re.search(r"GNU C Library \(Debian GLIBC ([^)]+)\)", strings_output)
    if match:
        return match.group(1)
    return None

def infer_ubuntu_release_from_libc(libc_path):
    pkg_ver = get_ubuntu_glibc_package_version(libc_path)
    if pkg_ver:
        glibc_ver = pkg_ver.split('-', 1)[0]
        for ubuntu_ver, mapped_glibc in UBUNTU_GLIBC_MAP.items():
            if mapped_glibc == glibc_ver:
                return ubuntu_ver
    versions = get_glibc_version_from_elf(libc_path)
    for ver in versions:
        if ver.startswith('ubuntu_') and 'inferred' not in ver:
            return ver.replace('ubuntu_', '')
    for ver in versions:
        if ver.startswith('likely_glibc_'):
            target_glibc = ver.replace('likely_glibc_', '')
            for ubuntu_ver, mapped_glibc in UBUNTU_GLIBC_MAP.items():
                if mapped_glibc == target_glibc:
                    return ubuntu_ver
    return None

def infer_debian_release_from_libc(libc_path):
    pkg_ver = get_debian_glibc_package_version(libc_path)
    if pkg_ver:
        debian_suffix_match = re.search(r'\+deb(\d+)u\d+', pkg_ver)
        if debian_suffix_match:
            return debian_suffix_match.group(1)
        glibc_ver = pkg_ver.split('-', 1)[0]
        for debian_release, mapped_glibc in DEBIAN_GLIBC_MAP.items():
            if debian_release.isdigit() and mapped_glibc == glibc_ver:
                return debian_release
    versions = get_glibc_version_from_elf(libc_path)
    for ver in versions:
        if ver.startswith('debian_') and 'inferred' not in ver:
            return ver.replace('debian_', '')
    for ver in versions:
        if ver.startswith('likely_glibc_'):
            target_glibc = ver.replace('likely_glibc_', '')
            for debian_release, mapped_glibc in DEBIAN_GLIBC_MAP.items():
                if mapped_glibc == target_glibc:
                    return debian_release
    return None

def normalize_debian_release(release):
    if not release:
        return None
    return DEBIAN_CODENAME_MAP.get(str(release).strip().lower())

def cached_file_analysis(file_path):
    abs_path = os.path.abspath(file_path)
    try:
        stat_result = os.stat(abs_path)
    except OSError:
        return {
            'strings': '',
            'objdump_t': '',
            'comment': '',
            'readelf_hn': '',
            'readelf_version': '',
        }
    cache_key = (abs_path, stat_result.st_mtime_ns, stat_result.st_size)
    cached = FILE_ANALYSIS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    analysis = {
        'strings': '',
        'objdump_t': '',
        'comment': '',
        'readelf_hn': '',
        'readelf_version': '',
    }
    commands = (
        ('strings', ['strings', abs_path], None, 20),
        ('objdump_t', ['objdump', '-T', abs_path], None, 15),
        ('comment', ['readelf', '-p', '.comment', abs_path], readelf_env(), 10),
        ('readelf_hn', ['readelf', '-h', '-n', abs_path], readelf_env(), 10),
        ('readelf_version', ['readelf', '--version-info', abs_path], readelf_env(), 10),
    )
    for field, command, env, timeout in commands:
        try:
            analysis[field] = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            ).stdout
        except Exception:
            analysis[field] = ''
    FILE_ANALYSIS_CACHE[cache_key] = analysis
    return analysis

def ensure_ubuntu_repo_root(base_url):
    repo_root = (base_url or '').rstrip('/')
    if not repo_root:
        return None
    if not repo_root.endswith('/ubuntu'):
        repo_root += '/ubuntu'
    return repo_root

def ensure_debian_repo_root(base_url):
    repo_root = (base_url or '').rstrip('/')
    if not repo_root:
        return None
    return repo_root

def iter_ubuntu_package_indexes(ubuntu_release, arch):
    codename = UBUNTU_CODENAME_MAP.get(ubuntu_release)
    if not codename:
        return
    archive_base = ensure_ubuntu_repo_root(
        os.environ.get('PWN_UBUNTU_ARCHIVE_URL', 'http://archive.ubuntu.com')
    )
    security_base = ensure_ubuntu_repo_root(
        os.environ.get('PWN_UBUNTU_SECURITY_URL', 'http://security.ubuntu.com')
    )
    old_releases_base = ensure_ubuntu_repo_root(
        os.environ.get('PWN_UBUNTU_OLD_RELEASES_URL', 'http://old-releases.ubuntu.com')
    )
    pocket_roots = [
        (f'{codename}-updates', archive_base),
        (f'{codename}-security', security_base),
        (codename, archive_base),
        (f'{codename}-updates', old_releases_base),
        (f'{codename}-security', old_releases_base),
        (codename, old_releases_base),
    ]
    components = ['main', 'universe', 'multiverse', 'restricted']
    seen = set()
    for pocket, repo_root in pocket_roots:
        if not repo_root:
            continue
        for component in components:
            index_url = f'{repo_root}/dists/{pocket}/{component}/binary-{arch}/Packages.gz'
            if index_url in seen:
                continue
            seen.add(index_url)
            yield (
                repo_root,
                index_url,
            )

def iter_debian_package_indexes(debian_release, arch):
    requested_codename = normalize_debian_release(debian_release)
    current_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_ARCHIVE_URL', 'https://deb.debian.org/debian')
    )
    security_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_SECURITY_URL', 'https://security.debian.org/debian-security')
    )
    archive_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_OLD_RELEASES_URL', 'https://archive.debian.org/debian')
    )
    archive_security_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_OLD_SECURITY_URL', 'https://archive.debian.org/debian-security')
    )

    codenames = []
    if requested_codename:
        codenames.append(requested_codename)
    elif debian_release:
        codenames.append(str(debian_release).strip())
    codenames.extend(DEBIAN_CODENAME_SEARCH_ORDER)

    seen_codenames = set()
    ordered_codenames = []
    for codename in codenames:
        if not codename or codename in seen_codenames:
            continue
        seen_codenames.add(codename)
        ordered_codenames.append(codename)

    components = ['main']
    seen = set()
    for codename in ordered_codenames:
        suite_roots = [
            (codename, current_base),
            (f'{codename}-updates', current_base),
            (f'{codename}-security', security_base),
            (codename, archive_base),
            (f'{codename}-updates', archive_base),
            (f'{codename}/updates', archive_security_base),
            (f'{codename}-security', archive_security_base),
        ]
        for suite, repo_root in suite_roots:
            if not repo_root:
                continue
            for component in components:
                for suffix in ('.gz', '.xz'):
                    index_url = f'{repo_root}/dists/{suite}/{component}/binary-{arch}/Packages{suffix}'
                    if index_url in seen:
                        continue
                    seen.add(index_url)
                    yield repo_root, index_url

def iter_ubuntu_debug_package_indexes(ubuntu_release, arch):
    codename = UBUNTU_CODENAME_MAP.get(ubuntu_release)
    if not codename:
        return
    ddebs_base = ensure_debian_repo_root(
        os.environ.get('PWN_UBUNTU_DDEBS_URL', 'http://ddebs.ubuntu.com')
    )
    pockets = [
        codename,
        f'{codename}-updates',
        f'{codename}-security',
        f'{codename}-proposed',
    ]
    components = ['main', 'universe', 'multiverse', 'restricted']
    seen = set()
    for pocket in pockets:
        for component in components:
            for suffix in ('.gz', '.xz'):
                index_url = f'{ddebs_base}/dists/{pocket}/{component}/binary-{arch}/Packages{suffix}'
                if index_url in seen:
                    continue
                seen.add(index_url)
                yield ddebs_base, index_url

def iter_debian_debug_package_indexes(debian_release, arch):
    requested_codename = normalize_debian_release(debian_release)
    debug_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_DEBUG_URL', 'https://deb.debian.org/debian-debug')
    )
    archive_debug_base = ensure_debian_repo_root(
        os.environ.get('PWN_DEBIAN_OLD_DEBUG_URL', 'https://archive.debian.org/debian-debug')
    )
    codenames = []
    if requested_codename:
        codenames.append(requested_codename)
    elif debian_release:
        codenames.append(str(debian_release).strip())
    if not codenames:
        codenames.extend(DEBIAN_CODENAME_SEARCH_ORDER)

    seen_codenames = set()
    ordered_codenames = []
    for codename in codenames:
        if not codename or codename in seen_codenames:
            continue
        seen_codenames.add(codename)
        ordered_codenames.append(codename)

    seen = set()
    for codename in ordered_codenames:
        suites = [
            f'{codename}-debug',
            f'{codename}-updates-debug',
            f'{codename}-security-debug',
            f'{codename}-proposed-updates-debug',
        ]
        for repo_root in (debug_base, archive_debug_base):
            if not repo_root:
                continue
            for suite in suites:
                for suffix in ('.xz', '.gz'):
                    index_url = f'{repo_root}/dists/{suite}/main/binary-{arch}/Packages{suffix}'
                    if index_url in seen:
                        continue
                    seen.add(index_url)
                    yield repo_root, index_url

def iter_debian_control_entries(text):
    entry = {}
    current_key = None
    for line in text.splitlines():
        if not line:
            if entry:
                yield entry
                entry = {}
                current_key = None
            continue
        if line[0].isspace() and current_key:
            entry[current_key] += '\n' + line[1:]
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        current_key = key.strip()
        entry[current_key] = value.strip()
    if entry:
        yield entry

def decode_debian_package_index(raw_data, index_url):
    if index_url.endswith('.gz'):
        return gzip.decompress(raw_data).decode(errors='ignore')
    if index_url.endswith('.xz'):
        return lzma.decompress(raw_data).decode(errors='ignore')
    return raw_data.decode(errors='ignore')

def iter_deb_package_urls(package_names, distro, release, arch, package_version=None, package_filename=None):
    if not package_names or not distro or not arch:
        return
    wanted = set(package_names)
    package_order = {name: index for index, name in enumerate(package_names)}
    distro_label = 'Ubuntu' if distro == 'ubuntu' else 'Debian'
    if distro == 'ubuntu':
        index_iter = iter_ubuntu_package_indexes(release, arch)
    elif distro == 'debian':
        index_iter = iter_debian_package_indexes(release, arch)
    else:
        return
    seen_urls = set()
    for repo_root, index_url in index_iter:
        try:
            raw_data = libcdb.wget(index_url, timeout=20)
            if not raw_data:
                continue
            index_text = decode_debian_package_index(raw_data, index_url)
        except Exception as e:
            log.warning(f"获取 {distro_label} 包索引失败: {index_url} ({e})")
            continue
        core_args = [
            'filter-package-urls',
            repo_root,
            arch,
            ','.join(package_names),
            package_version or '',
            package_filename or '',
        ]
        core_output = run_rust_core(core_args, index_text, timeout=10)
        if core_output is not None:
            for package_url in core_output.splitlines():
                package_url = package_url.strip()
                if not package_url or package_url in seen_urls:
                    continue
                seen_urls.add(package_url)
                yield package_url
            continue
        entries = []
        for entry in iter_debian_control_entries(index_text):
            if entry.get('Package') not in wanted:
                continue
            entry_arch = entry.get('Architecture')
            if entry_arch not in {arch, 'all'}:
                continue
            if package_version and entry.get('Version') != package_version:
                continue
            filename = entry.get('Filename')
            if not filename:
                continue
            basename = os.path.basename(filename)
            if package_filename and basename != package_filename:
                continue
            package_name = entry.get('Package')
            arch_score = 0 if entry_arch == arch else 1
            entries.append((package_order.get(package_name, len(package_order)), arch_score, entry))
        for _package_rank, _arch_score, entry in sorted(entries, key=lambda item: item[:2]):
            filename = entry.get('Filename')
            package_url = f"{repo_root}/{filename.lstrip('/')}"
            if package_url in seen_urls:
                continue
            seen_urls.add(package_url)
            yield package_url

def find_deb_package_url(package_names, distro, release, arch, package_version=None, package_filename=None):
    if not package_names or not distro or not arch:
        return None
    exact_match_required = bool(package_version or package_filename)
    for package_url in iter_deb_package_urls(
        package_names,
        distro,
        release,
        arch,
        package_version=package_version,
        package_filename=package_filename,
    ):
        return package_url
    if exact_match_required:
        return None
    return None

def find_deb_debug_package_url(package_names, distro, release, arch, package_version=None, package_filename=None):
    if not package_names or not distro or not arch:
        return None
    wanted = set(package_names)
    distro_label = 'Ubuntu' if distro == 'ubuntu' else 'Debian'
    if distro == 'ubuntu':
        index_iter = iter_ubuntu_debug_package_indexes(release, arch)
    elif distro == 'debian':
        index_iter = iter_debian_debug_package_indexes(release, arch)
    else:
        return None
    for repo_root, index_url in index_iter:
        try:
            raw_data = libcdb.wget(index_url, timeout=20)
            if not raw_data:
                continue
            index_text = decode_debian_package_index(raw_data, index_url)
        except Exception as e:
            log.warning(f"获取 {distro_label} debug 包索引失败: {index_url} ({e})")
            continue
        for entry in iter_debian_control_entries(index_text):
            if entry.get('Package') not in wanted:
                continue
            entry_arch = entry.get('Architecture')
            if entry_arch not in {arch, 'all'}:
                continue
            if package_version and entry.get('Version') != package_version:
                continue
            filename = entry.get('Filename')
            if not filename:
                continue
            basename = os.path.basename(filename)
            if package_filename and basename != package_filename:
                continue
            return f"{repo_root}/{filename.lstrip('/')}"
    return None

def find_ubuntu_package_url(package_names, ubuntu_release, arch, package_version=None, package_filename=None):
    return find_deb_package_url(
        package_names,
        'ubuntu',
        ubuntu_release,
        normalize_deb_arch_name(arch),
        package_version=package_version,
        package_filename=package_filename,
    )

def find_debian_package_url(package_names, debian_release, arch, package_version=None, package_filename=None):
    return find_deb_package_url(
        package_names,
        'debian',
        debian_release,
        normalize_deb_arch_name(arch),
        package_version=package_version,
        package_filename=package_filename,
    )

def find_matching_ubuntu_libc_package_url(libc_path):
    ubuntu_release = infer_ubuntu_release_from_libc(libc_path)
    if not ubuntu_release:
        return None

    arch = normalize_deb_arch_name(get_elf_arch(libc_path))
    if arch == 'unknown':
        log.warning("无法识别 libc 架构，无法回退到仓库索引下载 libc")
        return None

    package_version = get_ubuntu_glibc_package_version(libc_path)
    if not package_version:
        log.warning("无法识别 libc 对应的 Ubuntu 包版本，无法回退到仓库索引下载 libc")
        return None

    package_filename = f'libc6_{package_version}_{arch}.deb'
    package_url = find_ubuntu_package_url(
        ['libc6'],
        ubuntu_release,
        arch,
        package_version=package_version,
        package_filename=package_filename,
    )
    if not package_url:
        log.warning(
            f"未在 Ubuntu 仓库索引中找到精确匹配的 libc 包: "
            f"{stderr_name(package_filename)} (Ubuntu {stderr_version(ubuntu_release)})"
        )
        return None

    log.info(
        f"仓库索引命中 libc 包: {stderr_path(package_url)} "
        f"(Ubuntu {stderr_version(ubuntu_release)}, 架构 {stderr_version(arch)})"
    )
    return package_url

def find_matching_debian_libc_package_url(libc_path):
    if not get_debian_glibc_package_version(libc_path):
        return None
    debian_release = infer_debian_release_from_libc(libc_path)
    arch = normalize_deb_arch_name(get_elf_arch(libc_path))
    if arch == 'unknown':
        log.warning("无法识别 libc 架构，无法回退到 Debian 仓库索引下载 libc")
        return None

    package_version = get_debian_glibc_package_version(libc_path)
    if not package_version:
        log.warning("无法识别 libc 对应的 Debian 包版本，无法回退到 Debian 仓库索引下载 libc")
        return None

    package_filename = f'libc6_{package_version}_{arch}.deb'
    package_url = find_debian_package_url(
        ['libc6'],
        debian_release,
        arch,
        package_version=package_version,
        package_filename=package_filename,
    )
    if not package_url:
        release_text = f"Debian {debian_release}" if debian_release else "Debian 仓库"
        log.warning(
            f"未在 Debian 仓库索引中找到精确匹配的 libc 包: "
            f"{stderr_name(package_filename)} ({stderr_version(release_text)})"
        )
        return None

    log.info(
        f"仓库索引命中 libc 包: {stderr_path(package_url)} "
        f"(Debian {stderr_version(debian_release or 'auto')}, 架构 {stderr_version(arch)})"
    )
    return package_url

def parse_deb_package_filename(package_url):
    basename = os.path.basename(package_url or '')
    match = re.match(r'(?P<name>[A-Za-z0-9.+-]+)_(?P<version>.+)_(?P<arch>[A-Za-z0-9]+)\.d(?:d)?eb$', basename)
    if not match:
        return None
    return match.groupdict()

def derive_ubuntu_debug_package_urls(package_url):
    info = parse_deb_package_filename(package_url)
    if not info:
        return []
    version = info['version']
    arch = info['arch']
    base_dir = package_url.rsplit('/', 1)[0] if '/' in package_url else ''
    candidates = []
    if base_dir:
        candidates.extend([
            f'{base_dir}/libc6-dbg_{version}_{arch}.deb',
            f'{base_dir}/libc6-dbgsym_{version}_{arch}.ddeb',
            f'{base_dir}/libc6-dbgsym_{version}_{arch}.deb',
        ])
    candidates.extend([
        f'https://launchpad.net/ubuntu/+archive/primary/+files/libc6-dbg_{version}_{arch}.deb',
        f'https://launchpad.net/ubuntu/+archive/primary/+files/libc6-dbgsym_{version}_{arch}.ddeb',
        f'http://ddebs.ubuntu.com/pool/main/g/glibc/libc6-dbgsym_{version}_{arch}.ddeb',
        f'http://ddebs.ubuntu.com/pool/main/e/eglibc/libc6-dbg_{version}_{arch}.deb',
    ])
    deduped = []
    seen = set()
    for candidate in candidates:
        normalized = re.sub(r'(?<!:)//+', '/', candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped

def iter_matching_debug_package_urls(package_url, distro=None, release=None):
    info = parse_deb_package_filename(package_url)
    if not info:
        return
    version = info['version']
    arch = info['arch']
    if distro == 'ubuntu' or 'ubuntu' in version:
        for candidate_url in derive_ubuntu_debug_package_urls(package_url):
            yield candidate_url
    if distro == 'debian' or '+deb' in version:
        debian_release = release
        deb_match = re.search(r'\+deb(\d+)u\d+', version)
        if deb_match:
            debian_release = deb_match.group(1)
        debug_url = find_deb_debug_package_url(
            ['libc6-dbg', 'libc6-dbgsym'],
            'debian',
            debian_release,
            arch,
            package_version=version,
        )
        if debug_url:
            yield debug_url

def find_matching_debug_package_url(package_url, distro=None, release=None):
    return next(iter_matching_debug_package_urls(package_url, distro=distro, release=release), None)

def find_local_libc_database_url(libc_path):
    abs_path = os.path.abspath(libc_path)
    db_path = os.path.abspath(LIBC_DB_PATH)
    try:
        in_db = os.path.commonpath([abs_path, db_path]) == db_path
    except ValueError:
        in_db = False
    if not in_db:
        return None
    url_path = os.path.splitext(abs_path)[0] + '.url'
    if not os.path.exists(url_path):
        return None
    try:
        with open(url_path, 'r') as f:
            package_url = f.read().strip()
    except OSError:
        return None
    if not package_url:
        return None
    return re.sub(r'(?<!:)//+', '/', package_url)

def elf_has_dynamic_section(elf_path):
    fast_info = inspect_elf_fast(elf_path)
    if fast_info is not None:
        return bool(fast_info.get('has_dynamic'))
    try:
        result = subprocess.run(
            ['readelf', '-d', elf_path],
            capture_output=True,
            text=True,
            timeout=10,
            env=readelf_env(),
        )
    except Exception:
        return False
    output = (result.stdout or '') + (result.stderr or '')
    return result.returncode == 0 and 'There is no dynamic section' not in output

def copy_debug_only_artifact(source_file, target_file):
    debug_target = target_file + '.debug'
    if os.path.exists(debug_target):
        return None
    shutil.copy2(source_file, debug_target)
    return debug_target

def copy_shared_object_artifacts(source_dir, target_dir, wanted_names=None, overwrite=False, require_dynamic=False):
    os.makedirs(target_dir, exist_ok=True)
    copied = []
    seen = set()
    wanted = set(wanted_names or ())
    for root, _dirs, files in os.walk(source_dir):
        for file_name in sorted(files):
            if not is_shared_object_artifact(file_name):
                continue
            if wanted and (
                file_name not in wanted
                and not any(file_name.startswith(name + '.') for name in wanted)
            ):
                continue
            source_file = os.path.join(root, file_name)
            if not os.path.isfile(source_file):
                continue
            target_file = os.path.join(target_dir, file_name)
            if target_file in seen:
                continue
            if require_dynamic and is_elf_file(source_file) and not elf_has_dynamic_section(source_file):
                debug_copy = copy_debug_only_artifact(source_file, target_file)
                if debug_copy:
                    copied.append(debug_copy)
                seen.add(target_file)
                continue
            if os.path.exists(target_file) and not overwrite:
                seen.add(target_file)
                continue
            shutil.copy2(source_file, target_file)
            copied.append(target_file)
            seen.add(target_file)
    return copied

def runtime_libc_target_names(libc_path):
    names = ['libc.so.6']
    basename = os.path.basename(libc_path)
    if re.fullmatch(r'libc-\d+(?:\.\d+)*\.so', basename):
        names.append(basename)
    else:
        file_ver, _file_arch = parse_filename_id(basename)
        if file_ver:
            names.append(f'libc-{file_ver}.so')
    return list(dict.fromkeys(names))

def is_same_elf_build_id(left_path, right_path):
    if not left_path or not right_path:
        return False
    if not os.path.exists(left_path) or not os.path.exists(right_path):
        return False
    if not is_elf_file(left_path) or not is_elf_file(right_path):
        return False
    left_build_id, _left_arch = inspect_elf_metadata(left_path)
    right_build_id, _right_arch = inspect_elf_metadata(right_path)
    return bool(left_build_id and right_build_id and left_build_id == right_build_id)

def copy_runtime_libc(libc_path, target_dir, overwrite=False):
    if not libc_path or not os.path.exists(libc_path):
        return []
    if not is_elf_file(libc_path) or not elf_has_dynamic_section(libc_path):
        return []
    copied = []
    for name in runtime_libc_target_names(libc_path):
        target_file = os.path.join(target_dir, name)
        if os.path.exists(target_file) and is_elf_file(target_file) and not elf_has_dynamic_section(target_file):
            copy_debug_only_artifact(target_file, target_file)
        elif os.path.exists(target_file) and not overwrite:
            if is_same_elf_build_id(target_file, libc_path) and elf_has_debug_symbols(target_file):
                continue
        shutil.copy2(libc_path, target_file)
        copied.append(target_file)
    return copied

def safe_member_target_path(dest_root, member_name):
    member_path = os.path.abspath(os.path.join(dest_root, member_name))
    if not member_path.startswith(dest_root + os.sep) and member_path != dest_root:
        raise ValueError(f"archive path escapes target dir: {member_name}")
    return member_path

def sanitize_tar_link_member(member, dest_root):
    if not (member.issym() or member.islnk()):
        return member
    link_name = member.linkname or ''
    if not link_name:
        return member

    member_path = safe_member_target_path(dest_root, member.name)
    if os.path.isabs(link_name):
        target_path = safe_member_target_path(dest_root, link_name.lstrip('/'))
    else:
        target_path = os.path.abspath(os.path.join(os.path.dirname(member_path), link_name))
        if not target_path.startswith(dest_root + os.sep) and target_path != dest_root:
            raise ValueError(f"archive link escapes target dir: {member.name} -> {link_name}")

    if member.issym():
        safe_link_name = os.path.relpath(target_path, os.path.dirname(member_path))
    else:
        safe_link_name = os.path.relpath(target_path, dest_root)
    return member.replace(linkname=safe_link_name)

def safe_extract_tar(tar_obj, dest_dir):
    dest_root = os.path.abspath(dest_dir)
    members = []
    for member in tar_obj.getmembers():
        safe_member_target_path(dest_root, member.name)
        members.append(sanitize_tar_link_member(member, dest_root))
    try:
        tar_obj.extractall(dest_dir, members=members, filter='fully_trusted')
    except TypeError:
        tar_obj.extractall(dest_dir, members=members)

def extract_all_from_deb_with_system_tools(cache_dir, package_filename, package_data):
    ar_path = shutil.which('ar')
    bsdtar_path = shutil.which('bsdtar')
    if not ar_path and not bsdtar_path:
        raise RuntimeError("missing unix_ar and no system ar/bsdtar available")

    package_tmp = None
    unpack_dir = None
    try:
        fd, package_tmp = tempfile.mkstemp(prefix=package_filename + '.', suffix='.deb')
        with os.fdopen(fd, 'wb') as f:
            f.write(package_data)

        if ar_path:
            unpack_dir = tempfile.mkdtemp(prefix='libc-tool-deb-')
            result = subprocess.run(
                [ar_path, 't', package_tmp],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or '').strip()
                raise RuntimeError(f"ar list failed: {detail}")
            members = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            data_name = next((name for name in members if name.startswith('data.tar')), None)
            if not data_name:
                raise ValueError(f"missing data.tar in {package_filename}")
            result = subprocess.run(
                [ar_path, 'x', package_tmp, data_name],
                cwd=unpack_dir,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or '').strip()
                raise RuntimeError(f"ar extract failed: {detail}")
            tar_path = os.path.join(unpack_dir, data_name)
            with tarfile.open(tar_path, mode='r:*') as tar_obj:
                safe_extract_tar(tar_obj, cache_dir)
            return

        result = subprocess.run(
            [bsdtar_path, '-xf', package_tmp, '-C', cache_dir],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or '').strip()
            raise RuntimeError(f"bsdtar extract failed: {detail}")
    finally:
        if unpack_dir:
            shutil.rmtree(unpack_dir, ignore_errors=True)
        if package_tmp and os.path.exists(package_tmp):
            try:
                os.unlink(package_tmp)
            except OSError:
                pass

def extract_all_from_deb(cache_dir, package_filename, package_data):
    try:
        import unix_ar
    except ImportError:
        extract_all_from_deb_with_system_tools(cache_dir, package_filename, package_data)
        return
    from io import BytesIO

    ar_file = unix_ar.open(BytesIO(package_data))
    try:
        data_name = next(
            (info.name.decode() for info in ar_file.infolist() if info.name.startswith(b'data.tar')),
            None,
        )
        if not data_name:
            raise ValueError(f"missing data.tar in {package_filename}")
        tar_stream = ar_file.open(data_name)
        if data_name.endswith(('.zst', '.zstd')):
            import zstandard
            decompressed = BytesIO()
            zstandard.ZstdDecompressor().copy_stream(tar_stream, decompressed)
            decompressed.seek(0)
            tar_stream.close()
            tar_stream = decompressed
        with tarfile.open(fileobj=tar_stream, mode='r:*') as tar_obj:
            safe_extract_tar(tar_obj, cache_dir)
    finally:
        ar_file.close()

def download_and_extract_deb_package(package_url, cache_key):
    cache_root = os.path.join(ensure_pwntools_cache_dir(), 'libc_tool_extra_libs')
    cache_dir = os.path.join(cache_root, cache_key)
    if os.path.isdir(cache_dir) and any(os.scandir(cache_dir)):
        return cache_dir
    shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)
    try:
        package_data = libcdb.wget(package_url, timeout=20)
        if not package_data:
            return None
        extract_all_from_deb(cache_dir, os.path.basename(package_url), package_data)
    except Exception as e:
        shutil.rmtree(cache_dir, ignore_errors=True)
        log.warning(f"下载或解压额外依赖失败: {package_url} ({e})")
        return None
    return cache_dir

def elf_has_debug_symbols(elf_path):
    fast_info = inspect_elf_fast(elf_path)
    if fast_info is not None:
        return bool(fast_info.get('has_debug'))
    try:
        result = subprocess.run(
            ['readelf', '-S', elf_path],
            capture_output=True,
            text=True,
            timeout=10,
            env=readelf_env(),
        )
    except Exception:
        return False
    if result.returncode != 0:
        return False
    return any(name in result.stdout for name in ('.debug_info', '.symtab'))

def find_libc_files_in_tree(root_dir):
    candidates = []
    for root, _dirs, files in os.walk(root_dir):
        for file_name in sorted(files):
            if file_name == 'libc.so.6' or re.fullmatch(r'libc-\d+(?:\.\d+)*\.so', file_name):
                candidate = os.path.join(root, file_name)
                if os.path.isfile(candidate):
                    candidates.append(candidate)
    return candidates

def find_debug_files_in_tree(root_dir):
    candidates = []
    for root, _dirs, files in os.walk(root_dir):
        for file_name in sorted(files):
            candidate = os.path.join(root, file_name)
            if not os.path.isfile(candidate):
                continue
            if file_name.endswith('.debug') or is_elf_file(candidate):
                candidates.append(candidate)
    return candidates

def eu_unstrip_with_debug(libc_file, debug_file):
    if not shutil.which('eu-unstrip'):
        log.warning('找不到 eu-unstrip，无法合并 debug 符号；请安装 elfutils')
        return False
    tmp_path = None
    try:
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=os.path.basename(libc_file) + '.unstrip.',
                suffix='.so',
                dir=os.path.dirname(libc_file),
            )
            os.close(fd)
            result = subprocess.run(
                ['eu-unstrip', '-o', tmp_path, libc_file, debug_file],
                capture_output=True,
                text=True,
                timeout=30,
                env=readelf_env(),
            )
        except Exception as e:
            log.debug(f"eu-unstrip 执行失败: {e}")
            return False
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or '').strip()
            log.debug(f"eu-unstrip 合并失败: {libc_file} + {debug_file} ({detail})")
            return False
        if not elf_has_debug_symbols(tmp_path):
            return False
        shutil.copystat(libc_file, tmp_path)
        os.replace(tmp_path, libc_file)
        tmp_path = None
        return True
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

def unstrip_libc_tree_with_debug_package(libc_dir, debug_dir):
    for debug_libc in find_libc_files_in_tree(debug_dir):
        if elf_has_debug_symbols(debug_libc):
            for target_libc in find_libc_files_in_tree(libc_dir):
                if os.path.basename(target_libc) == os.path.basename(debug_libc) or os.path.basename(target_libc) == 'libc.so.6':
                    if elf_has_dynamic_section(debug_libc):
                        shutil.copy2(debug_libc, target_libc)
                        log.success(
                            f"debug 包提供完整未 strip libc: {stderr_path(target_libc)} "
                            f"<- {stderr_path(debug_libc)}"
                        )
                        return True
                    if eu_unstrip_with_debug(target_libc, debug_libc):
                        log.success(
                            f"已合并 debug 符号: {stderr_path(target_libc)} "
                            f"<- {stderr_path(debug_libc)}"
                        )
                        return True
                    debug_copy = copy_debug_only_artifact(debug_libc, target_libc)
                    if debug_copy:
                        log.info(f"debug-only libc 已另存: {stderr_path(debug_copy)}")
    debug_files = find_debug_files_in_tree(debug_dir)
    if not debug_files:
        log.warning("debug 包中未找到可用 debug 文件")
        return False
    for libc_file in find_libc_files_in_tree(libc_dir):
        if elf_has_debug_symbols(libc_file):
            return True
        for debug_file in debug_files:
            if eu_unstrip_with_debug(libc_file, debug_file):
                log.success(
                    f"已合并 debug 符号: {stderr_path(libc_file)} "
                    f"<- {stderr_path(debug_file)}"
                )
                return True
    return False

def fetch_debug_package_for_libc_package(package_url, cache_key, distro=None, release=None):
    attempted_url = None
    attempted_urls = []
    for debug_url in iter_matching_debug_package_urls(package_url, distro=distro, release=release):
        attempted_url = debug_url
        attempted_urls.append(debug_url)
        log.info(f"尝试下载 debug 包: {stderr_path(debug_url)}")
        debug_cache_key = hashlib.sha256(f'debug:{debug_url}'.encode()).hexdigest()[:16]
        debug_dir = download_and_extract_deb_package(debug_url, f'{cache_key}-dbg-{debug_cache_key}')
        if debug_dir:
            return debug_url, debug_dir
    if attempted_urls:
        log.warning(
            "debug 包候选均失败: " +
            ", ".join(stderr_path(url) for url in attempted_urls)
        )
    return attempted_url, None

def download_and_extract_libc_package_with_debug(package_url, cache_key, distro=None, release=None):
    extracted_dir = download_and_extract_deb_package(package_url, cache_key)
    if not extracted_dir:
        return None
    if any(elf_has_debug_symbols(path) for path in find_libc_files_in_tree(extracted_dir)):
        return extracted_dir
    debug_url, debug_dir = fetch_debug_package_for_libc_package(
        package_url,
        cache_key,
        distro=distro,
        release=release,
    )
    if debug_dir and unstrip_libc_tree_with_debug_package(extracted_dir, debug_dir):
        return extracted_dir
    if debug_url:
        log.warning(f"已下载 libc 包，但未能获取或合并未 strip 符号: {stderr_path(debug_url)}")
    else:
        log.warning("已下载 libc 包，但未找到对应 debug 包")
    return extracted_dir

def try_unstrip_libc_tree(libc_dir):
    if not libcdb or not hasattr(libcdb, 'unstrip_libc'):
        return None
    for candidate in find_libc_files_in_tree(libc_dir):
        if not elf_has_dynamic_section(candidate):
            continue
        backup_path = candidate + '.runtime.bak'
        try:
            shutil.copy2(candidate, backup_path)
            if libcdb.unstrip_libc(candidate):
                if elf_has_dynamic_section(candidate):
                    if elf_has_debug_symbols(candidate):
                        return candidate
                else:
                    copy_debug_only_artifact(candidate, candidate)
                    shutil.copy2(backup_path, candidate)
        except Exception as e:
            log.debug(f"libc unstrip 失败: {candidate} ({e})")
            if os.path.exists(backup_path):
                try:
                    shutil.copy2(backup_path, candidate)
                except OSError:
                    pass
        finally:
            if os.path.exists(backup_path):
                try:
                    os.unlink(backup_path)
                except OSError:
                    pass
    return None

def download_matching_ubuntu_libc_package(libc_path):
    package_url = find_matching_ubuntu_libc_package_url(libc_path)
    if not package_url:
        return None
    cache_key = hashlib.sha256(f'libc:{package_url}'.encode()).hexdigest()[:16]
    extracted_dir = download_and_extract_libc_package_with_debug(
        package_url,
        cache_key,
        distro='ubuntu',
        release=infer_ubuntu_release_from_libc(libc_path),
    )
    if not extracted_dir:
        return None
    try_unstrip_libc_tree(extracted_dir)
    return extracted_dir

def download_matching_debian_libc_package(libc_path):
    package_url = find_matching_debian_libc_package_url(libc_path)
    if not package_url:
        return None
    cache_key = hashlib.sha256(f'libc:{package_url}'.encode()).hexdigest()[:16]
    extracted_dir = download_and_extract_libc_package_with_debug(
        package_url,
        cache_key,
        distro='debian',
        release=infer_debian_release_from_libc(libc_path),
    )
    if not extracted_dir:
        return None
    try_unstrip_libc_tree(extracted_dir)
    return extracted_dir

def download_local_libc_database_package(libc_path):
    package_url = find_local_libc_database_url(libc_path)
    if not package_url:
        return None
    cache_key = hashlib.sha256(f'local-url:{package_url}'.encode()).hexdigest()[:16]
    distro = 'debian' if '+deb' in package_url else ('ubuntu' if 'ubuntu' in package_url else None)
    extracted_dir = download_and_extract_libc_package_with_debug(
        package_url,
        cache_key,
        distro=distro,
        release=infer_debian_release_from_libc(libc_path) if distro == 'debian' else infer_ubuntu_release_from_libc(libc_path),
    )
    if not extracted_dir:
        return None
    try_unstrip_libc_tree(extracted_dir)
    log.success(f'已通过本地 libc-database URL 下载 libc: {stderr_path(extracted_dir)}')
    return extracted_dir

def try_unstrip_cached_libc_dir_from_local_url(libc_path, libc_dir):
    if find_unstripped_libc_in_dir(libc_dir):
        return libc_dir
    package_url = find_local_libc_database_url(libc_path)
    if not package_url:
        return None
    distro = 'debian' if '+deb' in package_url else ('ubuntu' if 'ubuntu' in package_url else None)
    cache_key = hashlib.sha256(f'cached-local-url:{package_url}'.encode()).hexdigest()[:16]
    log.info(f"缓存 libc 未带符号，尝试通过本地 URL 补 debug 包: {stderr_path(package_url)}")
    debug_url, debug_dir = fetch_debug_package_for_libc_package(
        package_url,
        cache_key,
        distro=distro,
        release=infer_debian_release_from_libc(libc_path) if distro == 'debian' else infer_ubuntu_release_from_libc(libc_path),
    )
    if debug_dir and unstrip_libc_tree_with_debug_package(libc_dir, debug_dir):
        return libc_dir
    if debug_url:
        log.warning(f"缓存 libc debug 合并失败: {stderr_path(debug_url)}")

    refreshed_dir = download_and_extract_libc_package_with_debug(
        package_url,
        cache_key,
        distro=distro,
        release=infer_debian_release_from_libc(libc_path) if distro == 'debian' else infer_ubuntu_release_from_libc(libc_path),
    )
    if refreshed_dir and find_unstripped_libc_in_dir(refreshed_dir):
        return refreshed_dir
    return None

def download_matching_deb_libc_package(libc_path):
    extracted_dir = download_local_libc_database_package(libc_path)
    if extracted_dir:
        return extracted_dir

    candidates = []
    if get_ubuntu_glibc_package_version(libc_path):
        candidates.append(('Ubuntu', download_matching_ubuntu_libc_package))
    if get_debian_glibc_package_version(libc_path):
        candidates.append(('Debian', download_matching_debian_libc_package))
    if not candidates:
        candidates = [
            ('Ubuntu', download_matching_ubuntu_libc_package),
            ('Debian', download_matching_debian_libc_package),
        ]

    for distro, downloader in candidates:
        extracted_dir = downloader(libc_path)
        if extracted_dir:
            log.success(f'已通过 {distro} 仓库索引回退下载 libc: {stderr_path(extracted_dir)}')
            return extracted_dir
    if not find_local_libc_database_url(libc_path):
        log.warning("无法通过本地 URL 或 Ubuntu/Debian 仓库索引回退下载 libc")
    return None

def find_unstripped_libc_in_dir(target_dir):
    for libc_file in sorted(find_libc_files_in_tree(target_dir)):
        if elf_has_debug_symbols(libc_file):
            return libc_file
    return None

def find_libc_debug_symbol_file_in_dir(target_dir):
    for libc_file in sorted(find_libc_files_in_tree(target_dir)):
        debug_file = libc_file + '.debug'
        if os.path.exists(debug_file) and elf_has_debug_symbols(debug_file):
            return debug_file
    return None

def iter_repository_package_urls(package_names, distro, release, arch, package_version=None, package_filename=None):
    if distro == 'ubuntu':
        yield from iter_deb_package_urls(
            package_names,
            'ubuntu',
            release,
            normalize_deb_arch_name(arch),
            package_version=package_version,
            package_filename=package_filename,
        )
        return
    if distro == 'debian':
        yield from iter_deb_package_urls(
            package_names,
            'debian',
            release,
            normalize_deb_arch_name(arch),
            package_version=package_version,
            package_filename=package_filename,
        )

def find_repository_package_url(package_names, distro, release, arch, package_version=None, package_filename=None):
    return next(
        iter_repository_package_urls(
            package_names,
            distro,
            release,
            arch,
            package_version=package_version,
            package_filename=package_filename,
        ),
        None,
    )

def describe_library_abi_status(status):
    reason = status.get('reason')
    if reason == 'missing':
        return '未找到目标库文件'
    if reason == 'no_dynamic_section':
        return '目标库没有 dynamic section'
    if reason == 'missing_versions':
        return f"缺少版本: {summarize_abi_versions(status.get('missing', set()))}"
    if reason == 'runtime_libc_missing':
        return '目标运行时 libc 不存在'
    if reason == 'missing_runtime_versions':
        return f"依赖的 libc 版本不存在: {summarize_abi_versions(status.get('missing', set()))}"
    return reason or '未知原因'

def format_download_context(distro, release, arch):
    label = 'Ubuntu' if distro == 'ubuntu' else 'Debian'
    release_text = release or 'auto'
    return f"{label} {release_text}, 架构 {arch}"

def infer_download_context_from_libc(libc_path):
    arch = normalize_deb_arch_name(get_elf_arch(libc_path))
    if arch == 'unknown':
        log.warning("无法识别 libc 架构，跳过额外依赖补全")
        return None
    if get_ubuntu_glibc_package_version(libc_path):
        ubuntu_release = infer_ubuntu_release_from_libc(libc_path)
        return 'ubuntu', ubuntu_release, arch
    if get_debian_glibc_package_version(libc_path):
        debian_release = infer_debian_release_from_libc(libc_path)
        return 'debian', debian_release, arch
    ubuntu_release = infer_ubuntu_release_from_libc(libc_path)
    debian_release = infer_debian_release_from_libc(libc_path)
    if ubuntu_release:
        return 'ubuntu', ubuntu_release, arch
    if debian_release:
        return 'debian', debian_release, arch
    log.warning("无法推断目标 Ubuntu/Debian 版本，跳过额外依赖补全")
    return None

def download_extra_packages(libc_path, target_dir, extra_packages=None):
    packages = normalize_package_name_list(extra_packages)
    if not packages:
        return []

    download_context = infer_download_context_from_libc(libc_path)
    if not download_context:
        return []
    distro, release, arch = download_context

    copied = []
    log.info(
        f"检查额外包: 目标 {stderr_version(format_download_context(distro, release, arch))}, "
        f"指定 {stderr_number(len(packages))} 个"
    )
    for package_name in packages:
        package_url = find_repository_package_url([package_name], distro, release, arch)
        if not package_url:
            log.warning(f"未找到额外包 {stderr_name(package_name)}")
            continue
        cache_key = hashlib.sha256(f'pkg:{package_url}'.encode()).hexdigest()[:16]
        extracted_dir = download_and_extract_deb_package(package_url, cache_key)
        if not extracted_dir:
            continue
        copied_now = copy_shared_object_artifacts(extracted_dir, target_dir, require_dynamic=True)
        if copied_now:
            copied.extend(copied_now)
            copied_targets = ", ".join(stderr_path(path) for path in copied_now)
            log.success(f"拉取额外包 {stderr_name(package_name)} 来自 {stderr_path(package_url)} -> {copied_targets}")
        else:
            log.info(f"额外包 {stderr_name(package_name)} 未新增共享库文件")
    return copied

def download_missing_dependencies(libc_path, elf_path, target_dir, missing=None, extra_needed=None, package_hints=None):
    if not elf_path and not extra_needed:
        return []
    missing = list(missing if missing is not None else get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed))
    if not missing:
        return []

    download_context = infer_download_context_from_libc(libc_path)
    if not download_context:
        return []
    distro, release, arch = download_context

    copied = []
    log.info(
        f"检查额外依赖: 目标 {stderr_version(format_download_context(distro, release, arch))}, "
        f"缺失 {stderr_number(len(missing))} 个"
    )
    required_versions_by_soname = get_required_abi_versions_by_soname(elf_path)
    runtime_libc_path = find_library_artifact(target_dir, 'libc.so.6', require_dynamic=True)
    for soname in missing:
        package_names = guess_package_names_from_soname_with_hints(soname, package_hints=package_hints)
        if not package_names:
            log.warning(f"无法推断 {stderr_name(soname)} 对应的 Debian/Ubuntu 包")
            continue
        required_versions = required_versions_by_soname.get(soname, set())
        if required_versions:
            log.info(
                f"{stderr_name(soname)} 需要 ABI 版本: "
                f"{stderr_version(summarize_abi_versions(required_versions))}"
            )

        attempted = False
        satisfied = False
        for package_url in iter_repository_package_urls(package_names, distro, release, arch):
            attempted = True
            cache_key = hashlib.sha256(package_url.encode()).hexdigest()[:16]
            extracted_dir = download_and_extract_deb_package(package_url, cache_key)
            if not extracted_dir:
                continue
            candidate_lib = find_library_artifact(extracted_dir, soname, require_dynamic=True)
            status = library_satisfies_abi_requirements(
                candidate_lib,
                soname,
                required_versions=required_versions,
            )
            if not status['ok']:
                log.info(
                    f"跳过 {stderr_name(soname)} 候选包 {stderr_path(package_url)}: "
                    f"{describe_library_abi_status(status)}"
                )
                continue
            runtime_status = library_satisfies_runtime_libc(candidate_lib, runtime_libc_path)
            if not runtime_status['ok']:
                log.info(
                    f"跳过 {stderr_name(soname)} 候选包 {stderr_path(package_url)}: "
                    f"{describe_library_abi_status(runtime_status)}"
                )
                continue
            copied_now = copy_shared_object_artifacts(
                extracted_dir,
                target_dir,
                wanted_names={soname},
                overwrite=True,
                require_dynamic=True,
            )
            if copied_now:
                copied.extend(copied_now)
                copied_targets = ", ".join(stderr_path(path) for path in copied_now)
                log.success(f"补全依赖 {stderr_name(soname)} 来自 {stderr_path(package_url)} -> {copied_targets}")
            else:
                log.warning(f"已下载 {stderr_name(soname)} 对应包，但未复制目标库文件")
            satisfied = True
            break
        if not attempted:
            log.warning(f"未找到 {stderr_name(soname)} 的 Debian/Ubuntu 包（候选: {', '.join(package_names)}）")
        elif not satisfied:
            log.warning(f"未找到满足版本要求的 {stderr_name(soname)} 包（候选: {', '.join(package_names)}）")
    return copied

def load_index_cache():
    if os.path.exists(LIBC_INDEX_CACHE):
        try:
            with open(LIBC_INDEX_CACHE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"读取索引缓存失败: {e}")
    return None

def cache_source_mtime(db_path=LIBC_DB_PATH):
    return max(
        (
            os.path.getmtime(os.path.join(db_path, name))
            for name in os.listdir(db_path)
            if name.endswith(('.so', '.symbols', '.info'))
        ),
        default=0
    )

def index_cache_is_compatible(index):
    if not isinstance(index, dict):
        return False
    required_keys = {
        'schema_version',
        'by_id',
        'by_arch',
        'by_build_id',
        'by_build_id_prefix',
        'by_sha1',
        'by_version',
        'by_version_arch',
        'by_symbol_suffix',
        'versions_sorted',
        'entries',
    }
    return index.get('schema_version') == CACHE_SCHEMA_VERSION and required_keys.issubset(index)

def index_cache_is_fresh(cache_path=LIBC_INDEX_CACHE, db_path=LIBC_DB_PATH):
    if not os.path.exists(cache_path):
        return False
    return cache_source_mtime(db_path) <= os.path.getmtime(cache_path)

def parse_filename_id(filename):
    base = filename.replace('.so', '')
    version = None
    arch = None

    ver_match = re.search(r'_(\d+\.\d+(?:\.\d+)?)', base)
    if ver_match:
        version = ver_match.group(1)

    for arch_name in ['amd64', 'i386', 'x32', 'arm', 'aarch64', 'armhf', 'armel']:
        if base.endswith(arch_name) or base.endswith(arch_name + '_2'):
            arch = arch_name
            break

    return version, arch

def load_symbol_suffixes(symbols_path):
    symbol_suffixes = {}
    if not os.path.exists(symbols_path):
        return symbol_suffixes

    remaining = set(COMMON_LIBC_SYMBOLS)
    try:
        with open(symbols_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) != 2:
                    continue
                symbol_name, symbol_addr = parts
                if symbol_name not in remaining:
                    continue
                symbol_suffixes[symbol_name] = symbol_addr.lower()[-3:]
                remaining.remove(symbol_name)
                if not remaining:
                    break
    except Exception:
        pass

    return symbol_suffixes

def normalize_arch_name(arch):
    if arch in ('i386', 'i686'):
        return 'i386'
    if arch in ('amd64', 'x86_64'):
        return 'amd64'
    return arch or 'unknown'

def normalize_deb_arch_name(arch):
    arch = normalize_arch_name(arch)
    if arch == 'aarch64':
        return 'arm64'
    return arch

def parse_arch_from_readelf_output(output):
    class_match = re.search(r'Class:\s+(ELF32|ELF64)', output)
    machine_match = re.search(r'Machine:\s+(.+)', output)
    elf_class = class_match.group(1) if class_match else ""
    machine = machine_match.group(1).strip().lower() if machine_match else ""
    if "advanced micro devices x86-64" in machine or "x86-64" in machine:
        if elf_class == "ELF32":
            return "x32"
        return "amd64"
    if "intel 80386" in machine or "i386" in machine or "i686" in machine:
        return 'i386'
    if "aarch64" in machine:
        return "aarch64"
    if "arm" in machine:
        return "arm"
    return "unknown"

def inspect_elf_metadata(elf_path):
    build_id = None
    arch = "unknown"
    fast_info = inspect_elf_fast(elf_path)
    if fast_info is not None:
        build_id = fast_info.get('build_id')
        arch = normalize_arch_name(fast_info.get('arch', 'unknown'))
        if arch != "unknown":
            return build_id, arch
    try:
        output = cached_file_analysis(elf_path).get('readelf_hn', '')
        match = re.search(r'Build ID:\s*([a-f0-9]+)', output)
        build_id = match.group(1).lower() if match else None
        arch = parse_arch_from_readelf_output(output)
    except Exception as e:
        log.debug(f"readelf 元数据解析失败: {e}")

    if arch != "unknown":
        return build_id, arch

    if ELF is None:
        return build_id, arch

    try:
        with context.local(log_level='error'):
            elf = ELF(elf_path, checksec=False)
        arch = normalize_arch_name(elf.arch)
    except Exception as e:
        log.debug(f"pwnlib ELF 解析失败: {e}")
    return build_id, arch

def build_index_entry(so_file, db_path):
    so_path = os.path.join(db_path, so_file)
    entry_id = so_file.replace('.so', '')
    build_id, arch = inspect_elf_metadata(so_path)
    sha1 = sha1_of_file(so_path)
    file_ver, file_arch = parse_filename_id(so_file)
    if arch == 'unknown' and file_arch:
        arch = file_arch

    info = ""
    info_path = os.path.join(db_path, entry_id + '.info')
    if os.path.exists(info_path):
        with open(info_path, 'r') as f:
            info = f.read().strip()

    symbol_suffixes = load_symbol_suffixes(
        os.path.join(db_path, entry_id + '.symbols')
    )

    return {
        "id": entry_id,
        "path": so_path,
        "build_id": build_id,
        "sha1": sha1,
        "arch": arch,
        "version": file_ver,
        "info": info,
        "symbol_suffixes": symbol_suffixes,
    }

def index_build_worker_count(total):
    cpu_count = os.cpu_count() or 4
    return max(1, min(total, INDEX_BUILD_MAX_WORKERS, cpu_count))

def build_index_cache_with_rust(db_path=LIBC_DB_PATH, cache_path=LIBC_INDEX_CACHE, emit=None):
    if emit is None:
        emit = print
    core_path = find_rust_core_binary()
    if not core_path:
        return None
    total = sum(1 for name in os.listdir(db_path) if name.endswith('.so'))
    emit(
        f"{stdout_heading('Rust core scanning')} {stdout_number(total)} libc files..."
    )
    core_output = run_rust_core(
        [
            'build-index',
            db_path,
            str(CACHE_SCHEMA_VERSION),
            ','.join(COMMON_LIBC_SYMBOLS),
        ],
        '',
        timeout=120,
    )
    if core_output is None:
        return None
    try:
        index = json.loads(core_output)
    except json.JSONDecodeError as e:
        log.warning(f"Rust core 索引 JSON 解析失败: {e}")
        return None
    if not index_cache_is_compatible(index):
        log.warning("Rust core 生成的索引不兼容，回退 Python 索引构建")
        return None

    emit("")
    emit(stdout_ok("Rust index built:"))
    emit(f"  Entries: {stdout_number(len(index['entries']))}")
    emit(f"  Build IDs: {stdout_number(len(index['by_build_id']))}")
    emit(f"  SHA1 hashes: {stdout_number(len(index['by_sha1']))}")
    emit(f"  Versions: {stdout_number(len(index['by_version']))}")
    emit(f"  Symbol indices: {stdout_number(sum(len(v) for v in index['by_symbol_suffix'].values()))}")

    try:
        with open(cache_path, 'w') as f:
            json.dump(index, f)
        emit("")
        emit(f"{stdout_ok('Cache saved to:')} {stdout_path(cache_path)}")
    except OSError as e:
        log.warning(f"索引缓存写入失败，将使用内存索引继续: {e}")
    return index

def build_index_cache(db_path=LIBC_DB_PATH, cache_path=LIBC_INDEX_CACHE, emit=None):
    if emit is None:
        emit = print

    rust_index = build_index_cache_with_rust(db_path, cache_path, emit=emit)
    if rust_index is not None:
        return rust_index

    index = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "by_id": {},
        "by_arch": {},
        "by_build_id": {},
        "by_build_id_prefix": {},
        "by_sha1": {},
        "by_version": {},
        "by_version_arch": {},
        "by_symbol_suffix": {symbol: {} for symbol in COMMON_LIBC_SYMBOLS},
        "versions_sorted": [],
        "entries": []
    }

    so_files = sorted(name for name in os.listdir(db_path) if name.endswith('.so'))
    total = len(so_files)
    worker_count = index_build_worker_count(total)
    emit(
        f"{stdout_heading('Scanning')} {stdout_number(total)} libc files with "
        f"{stdout_number(worker_count)} workers..."
    )

    entry_builder = partial(build_index_entry, db_path=db_path)
    if worker_count == 1:
        entry_iter = map(entry_builder, so_files)
    else:
        executor = ThreadPoolExecutor(max_workers=worker_count)
        entry_iter = executor.map(entry_builder, so_files)

    try:
        for i, entry in enumerate(entry_iter):
            entry_id = entry["id"]

            if (i + 1) % 50 == 0 or i == 0:
                emit(
                    f"  [{stdout_number(i + 1)}/{stdout_number(total)}] "
                    f"{stdout_path(os.path.basename(entry['path']))}"
                )

            build_id = entry.get("build_id")
            sha1 = entry["sha1"]
            arch = entry.get("arch", "unknown")
            file_ver = entry.get("version")

            if build_id:
                index["by_build_id"].setdefault(build_id, []).append(entry_id)
                index["by_build_id_prefix"].setdefault(build_id[:16], []).append(entry_id)
            index["by_sha1"].setdefault(sha1, []).append(entry_id)
            index["by_arch"].setdefault(arch, []).append(entry_id)

            if file_ver:
                index["by_version"].setdefault(file_ver, []).append(entry_id)
                version_arch_bucket = index["by_version_arch"].setdefault(file_ver, {})
                version_arch_bucket.setdefault(arch, []).append(entry_id)

            index["entries"].append(entry)
            index["by_id"][entry_id] = len(index["entries"]) - 1

            for symbol_name, suffix in entry.get("symbol_suffixes", {}).items():
                index["by_symbol_suffix"][symbol_name].setdefault(suffix, []).append(entry_id)
    finally:
        if worker_count != 1:
            executor.shutdown(wait=True)

    index["versions_sorted"] = sorted(index["by_version"], key=version_tuple)

    emit("")
    emit(stdout_ok("Index built:"))
    emit(f"  Entries: {stdout_number(len(index['entries']))}")
    emit(f"  Build IDs: {stdout_number(len(index['by_build_id']))}")
    emit(f"  SHA1 hashes: {stdout_number(len(index['by_sha1']))}")
    emit(f"  Versions: {stdout_number(len(index['by_version']))}")
    emit(f"  Symbol indices: {stdout_number(sum(len(v) for v in index['by_symbol_suffix'].values()))}")

    try:
        with open(cache_path, 'w') as f:
            json.dump(index, f)
        emit("")
        emit(f"{stdout_ok('Cache saved to:')} {stdout_path(cache_path)}")
    except OSError as e:
        log.warning(f"索引缓存写入失败，将使用内存索引继续: {e}")
    return index

def rebuild_index_cache(force=False, quiet=False):
    if not os.path.exists(LIBC_DB_PATH):
        if quiet:
            return None
        log.error(f"数据库路径不存在: {stderr_path(LIBC_DB_PATH)}")
        return None

    current = load_index_cache()
    if not force and index_cache_is_compatible(current) and index_cache_is_fresh():
        if quiet:
            return current
        print(stdout_ok("Cache is up to date, skipping rebuild."))
        return current

    emit = (lambda *_args, **_kwargs: None) if quiet else print
    return build_index_cache(LIBC_DB_PATH, LIBC_INDEX_CACHE, emit=emit)

def ensure_index_cache():
    index = load_index_cache()
    if index_cache_is_compatible(index) and index_cache_is_fresh():
        return index

    if index is None:
        log.info("索引缓存不存在，正在自动构建...")
    elif not index_cache_is_compatible(index):
        log.info("索引缓存版本过旧，正在重建...")
    else:
        log.info("索引缓存已过期，正在重建...")

    index = rebuild_index_cache(force=True, quiet=True)
    if not index_cache_is_compatible(index):
        log.error("索引缓存构建失败")
        return None

    log.success("索引缓存构建完成")
    return index

def get_entry_by_id(index, entry_id):
    entry_pos = index.get('by_id', {}).get(entry_id)
    if isinstance(entry_pos, int) and 0 <= entry_pos < len(index.get('entries', [])):
        return index['entries'][entry_pos]

    for entry in index.get('entries', []):
        if entry.get('id') == entry_id:
            return entry
    return None

def symbol_count(entry):
    return len(entry.get('symbol_suffixes', {}))

def extract_release_tag(name):
    match = re.search(r'_(\d+\.\d+(?:\.\d+)?)-([^_]+)', name)
    return match.group(2) if match else ""

def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def version_sort_key(value):
    if not value or value == 'unknown':
        return ()
    match = re.match(r'(\d+(?:\.\d+)*)', str(value))
    if not match:
        return ()
    return version_tuple(match.group(1))

def extract_numbered_variant(name):
    stem = name[:-3] if name.endswith('.so') else name
    match = re.search(r'_(\d+)$', stem)
    return int(match.group(1)) if match else 0

def primary_variant_score(name):
    return 1 if extract_numbered_variant(name) == 0 else 0

def preferred_arch_package_score(name, target_arch):
    target_arch = normalize_arch_name(target_arch)
    if target_arch == 'unknown':
        return 0
    stem = name[:-3] if name.endswith('.so') else name
    if re.match(rf'^libc6_\d.*_{re.escape(target_arch)}(?:_\d+)?$', stem):
        return 3
    if re.match(rf'^libc6-{re.escape(target_arch)}_\d.*_', stem):
        return 2
    if stem.endswith(f'_{target_arch}') or re.search(rf'_{re.escape(target_arch)}_\d+$', stem):
        return 1
    return 0

def preferred_distro_package_score(name, info, target_ubuntu=None, target_debian=None):
    text_value = f"{name} {info}".lower()
    has_ubuntu = 'ubuntu' in text_value
    has_debian = 'debian' in text_value or '+deb' in text_value

    if target_ubuntu:
        if has_ubuntu:
            return 2
        if has_debian:
            return -2
    if target_debian:
        debian_codename = normalize_debian_release(target_debian)
        debian_version_tag = f"+deb{target_debian}".lower()
        if debian_version_tag in text_value:
            return 4
        if debian_codename and debian_codename in text_value:
            return 4
        if has_debian:
            return 2
        if has_ubuntu:
            return -2
    return 0

def match_types_for(match):
    match_types = match.get('match_types')
    if isinstance(match_types, list):
        return [item for item in match_types if item]
    match_type = match.get('match_type')
    return [match_type] if match_type else []

def match_type_rank(match):
    ranks = [MATCH_TYPE_RANK.get(match_type, 0) for match_type in match_types_for(match)]
    return max(ranks, default=0)

def natural_sort_key(value):
    parts = re.findall(r'\d+|[A-Za-z]+|[^A-Za-z\d]+', value)
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in parts
    )

def normalize_candidate_family(name):
    stem = name[:-3] if name.endswith('.so') else name
    stem = re.sub(r'_2$', '', stem)
    return stem

def libc_candidate_sort_key(match, target_arch='unknown'):
    name = match.get('name', '')
    return (
        safe_int(match.get('score')),
        match_type_rank(match),
        safe_int(match.get('evidence_count'), 1),
        safe_int(match.get('arch_score'), preferred_arch_package_score(name, target_arch)),
        safe_int(match.get('version_match_rank')),
        safe_int(match.get('distro_score')),
        safe_int(match.get('matched_symbol_count')),
        safe_int(match.get('symbol_count')),
        version_sort_key(match.get('glibc_ver')),
        natural_sort_key(extract_release_tag(name)),
        primary_variant_score(name),
    )

def merge_reason(existing_reason, new_reason):
    merged = []
    seen = set()
    for reason in (existing_reason, new_reason):
        for part in str(reason or '').split(', '):
            part = part.strip()
            if not part or part in seen:
                continue
            merged.append(part)
            seen.add(part)
    return ', '.join(merged)

def merge_match_types(existing, incoming):
    merged = []
    seen = set()
    for match_type in match_types_for(existing) + match_types_for(incoming):
        if match_type in seen:
            continue
        merged.append(match_type)
        seen.add(match_type)
    return merged

def merge_duplicate_matches(matches):
    by_path = {}
    for match in matches:
        path = match.get('path')
        if not path:
            continue
        current = by_path.get(path)
        if current is None:
            current = dict(match)
            current['match_types'] = match_types_for(match)
            current['evidence_count'] = len(current['match_types']) or 1
            by_path[path] = current
            continue

        current['reason'] = merge_reason(current.get('reason'), match.get('reason'))
        current['match_types'] = merge_match_types(current, match)
        current['evidence_count'] = len(current['match_types']) or 1

        if safe_int(match.get('score')) > safe_int(current.get('score')):
            current['score'] = match.get('score')
        if match_type_rank(match) > match_type_rank(current):
            current['match_type'] = match.get('match_type')

        for key in (
            'symbol_count',
            'matched_symbol_count',
            'version_match_rank',
            'distro_score',
            'arch_score',
        ):
            current[key] = max(safe_int(current.get(key)), safe_int(match.get(key)))

        for key in ('glibc_ver', 'arch', 'info', 'name'):
            if not current.get(key) or current.get(key) == 'unknown':
                current[key] = match.get(key, current.get(key))

    return list(by_path.values())

def deduplicate_candidates(matches):
    grouped = {}
    for match in matches:
        family = normalize_candidate_family(match.get('name', ''))
        grouped.setdefault(family, []).append(match)

    deduped = []
    for group in grouped.values():
        best = group[0]
        if len(group) > 1:
            best = dict(best)
            best['variants'] = len(group)
            best['reason'] = best.get('reason', '')
            if best['reason']:
                best['reason'] += f", grouped_variants_{len(group)}"
            else:
                best['reason'] = f"grouped_variants_{len(group)}"
        deduped.append(best)
    return deduped

def truncate_candidates(matches, candidate_limit):
    if candidate_limit is None or candidate_limit <= 0:
        return list(matches)
    return list(matches[:candidate_limit])

def build_id_from_elf(elf_path):
    build_id, _arch = inspect_elf_metadata(elf_path)
    return build_id

def should_try_build_id_match(elf_path):
    return is_libc_family_name(elf_path)

def sha1_of_file(file_path):
    h = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def get_elf_arch(elf_path):
    _build_id, arch = inspect_elf_metadata(elf_path)
    return arch

def extract_glibc_versions(text):
    return sorted(
        set(re.findall(r'GLIBC_([0-9]+(?:\.[0-9]+)+)', text)),
        key=version_tuple
    )

def get_required_glibc_version(elf_path):
    try:
        versions = extract_glibc_versions(cached_file_analysis(elf_path).get('objdump_t', ''))
        if versions:
            return versions[-1]
    except Exception:
        return None

def version_tuple(v):
    return tuple(map(int, v.split('.')))

def parse_debian_gcc_release(comment_text):
    debian_versions = []
    for match in re.finditer(r'GCC:\s+\(Debian\s+([0-9]+(?:\.[0-9]+)+)-[^)]*\)\s+([0-9]+(?:\.[0-9]+)+)', comment_text):
        debian_versions.extend(group for group in match.groups() if group)
    for gcc_version in debian_versions:
        release = DEBIAN_GCC_RELEASE_MAP.get(gcc_version)
        if release:
            return release, gcc_version
    for gcc_version in debian_versions:
        gcc_tuple = version_tuple(gcc_version)
        for min_version, release in (
            ("14.2.0", "13"),
            ("12.2.0", "12"),
            ("10.2.0", "11"),
            ("8.3.0", "10"),
            ("6.3.0", "9"),
            ("4.8.0", "8"),
            ("4.4.0", "7"),
        ):
            if gcc_tuple >= version_tuple(min_version):
                return release, gcc_version
    return None, None

def add_debian_release_hints(versions, release, gcc_version=None):
    if not release:
        return
    versions.add(f"debian_{release}" + (f" (inferred from GCC {gcc_version})" if gcc_version else ""))
    glibc_version = DEBIAN_GLIBC_MAP.get(release)
    if glibc_version:
        versions.add(f"likely_glibc_{glibc_version}")

def get_glibc_version_from_elf(elf_path):
    if not os.path.exists(elf_path):
        log.error(f"文件不存在: {elf_path}")
        return set()
    versions = set()
    analysis = cached_file_analysis(elf_path)
    objdump_output = analysis.get('objdump_t', '')
    try:
        glibc_matches = extract_glibc_versions(objdump_output)
        for v in glibc_matches:
            versions.add(f"glibc_{v}")
        if glibc_matches:
            max_ver = glibc_matches[-1]
            versions.add(f"required_glibc_{max_ver}")
            versions.add(f"max_glibc_{max_ver}")
    except Exception as e:
        log.debug(f"objdump GLIBC 分析失败: {e}")
    try:
        comment_output = analysis.get('comment', '')
        gcc_line = ""
        for line in comment_output.splitlines():
            if 'GCC: (' in line:
                gcc_line = line.strip()
                break
        debian_release, debian_gcc_version = parse_debian_gcc_release(comment_output)
        if debian_release:
            add_debian_release_hints(versions, debian_release, debian_gcc_version)
        if gcc_line:
            gcc_ver_match = re.search(r'(\d+)\.(\d+)\.(\d+)', gcc_line)
            if gcc_ver_match and 'Debian' not in gcc_line:
                major = f"{gcc_ver_match.group(1)}.{gcc_ver_match.group(2)}.{gcc_ver_match.group(3)}"
                gcc_ubuntu_exact = {
                    "15.1.0": "26.04",
                    "15.2.0": "25.10",
                    "14.3.0": "25.04",
                    "14.2.0": "24.10",
                    "13.3.0": "24.04.2",
                    "13.2.0": "24.04",
                    "13.1.0": "23.10",
                    "12.3.0": "23.04",
                    "12.2.0": "22.10",
                    "11.5.0": "22.04.5",
                    "11.4.0": "22.04.4",
                    "11.3.0": "22.04.3",
                    "11.2.0": "22.04",
                    "11.1.0": "21.10",
                    "10.5.0": "22.04-HWE",
                    "10.4.0": "20.04.5",
                    "10.3.0": "21.04",
                    "10.2.0": "20.10",
                    "9.5.0":  "20.04.4",
                    "9.4.0":  "20.04.3",
                    "9.3.0":  "20.04",
                    "8.4.0":  "18.04.5",
                    "8.3.0":  "19.04",
                    "7.5.0":  "18.04.4",
                    "7.4.0":  "18.04.3",
                    "7.3.0":  "18.04",
                    "6.5.0":  "18.04-HWE",
                    "6.4.0":  "17.10",
                    "6.3.0":  "17.04",
                    "5.5.0":  "16.04.5",
                    "5.4.0":  "16.04.4",
                    "5.3.0":  "16.04",
                    "4.9.4":  "16.04-old",
                    "4.9.3":  "15.10",
                    "4.9.2":  "15.04",
                    "4.8.5":  "14.04.5",
                    "4.8.4":  "14.04.4",
                    "4.8.2":  "14.04",
                }
                inferred_ubuntu = gcc_ubuntu_exact.get(major)
                if not inferred_ubuntu:
                    gcc_fallback = [
                        (version_tuple("15.1.0"), "26.04"),
                        (version_tuple("14.3.0"), "25.04"),
                        (version_tuple("14.2.0"), "24.10"),
                        (version_tuple("13.2.0"), "24.04"),
                        (version_tuple("12.3.0"), "23.04"),
                        (version_tuple("12.2.0"), "22.10"),
                        (version_tuple("11.2.0"), "22.04"),
                        (version_tuple("11.1.0"), "21.10"),
                        (version_tuple("10.3.0"), "21.04"),
                        (version_tuple("10.2.0"), "20.10"),
                        (version_tuple("9.3.0"),  "20.04"),
                        (version_tuple("8.3.0"),  "19.04"),
                        (version_tuple("7.3.0"),  "18.04"),
                        (version_tuple("6.3.0"),  "17.04"),
                        (version_tuple("5.3.0"),  "16.04"),
                        (version_tuple("4.9.2"),  "15.04"),
                        (version_tuple("4.8.2"),  "14.04"),
                    ]
                    for ver_tuple_val, ubuntu in gcc_fallback:
                        if version_tuple(major) >= ver_tuple_val:
                            inferred_ubuntu = ubuntu
                            break
                if inferred_ubuntu:
                    versions.add(f"ubuntu_{inferred_ubuntu} (inferred from GCC {major})")
                    # 尝试匹配到最近的 LTS 标准版本
                    ubuntu_to_lts = {
                        "26.04": "26.04", "25.10": "25.10", "25.04": "25.04",
                        "24.10": "24.10", "24.04.2": "24.04", "24.04": "24.04",
                        "23.10": "23.10", "23.04": "23.04", "22.10": "22.10",
                        "22.04.5": "22.04", "22.04.4": "22.04", "22.04.3": "22.04",
                        "22.04": "22.04", "22.04-HWE": "22.04",
                        "21.10": "21.10", "21.04": "21.04", "20.10": "20.10",
                        "20.04.5": "20.04", "20.04.4": "20.04", "20.04.3": "20.04",
                        "20.04": "20.04", "19.10": "19.10", "19.04": "19.04",
                        "18.04.5": "18.04", "18.04.4": "18.04", "18.04.3": "18.04",
                        "18.04": "18.04", "18.04-HWE": "18.04",
                        "17.10": "17.10", "17.04": "17.04",
                        "16.04.5": "16.04", "16.04.4": "16.04", "16.04": "16.04",
                        "16.04-old": "16.04",
                        "15.10": "15.10", "15.04": "15.04",
                        "14.04.5": "14.04", "14.04.4": "14.04", "14.04": "14.04",
                    }
                    lts_ver = ubuntu_to_lts.get(inferred_ubuntu, inferred_ubuntu)
                    if lts_ver in UBUNTU_GLIBC_MAP:
                        versions.add(f"likely_glibc_{UBUNTU_GLIBC_MAP[lts_ver]}")
    except Exception as e:
        log.debug(f"GCC 版本提取失败: {e}")

    if not versions:
        try:
            strings_output = analysis.get('strings', '')
            debian_release, debian_gcc_version = parse_debian_gcc_release(strings_output)
            if debian_release:
                add_debian_release_hints(versions, debian_release, debian_gcc_version)
            ubuntu_matches = re.findall(r'Ubuntu\s+([0-9]{2}\.[0-9]{2})', strings_output, re.I)
            for v in ubuntu_matches:
                versions.add(f"ubuntu_{v}")
                if v in UBUNTU_GLIBC_MAP:
                    versions.add(f"likely_glibc_{UBUNTU_GLIBC_MAP[v]}")
        except Exception as e:
            log.debug(f"OS 版本分析失败: {e}")
    return versions

def find_by_sha1(target_sha1, index):
    """Exact SHA1 match - fastest path"""
    entry_ids = index["by_sha1"].get(target_sha1, [])
    if isinstance(entry_ids, str):
        entry_ids = [entry_ids]
    matches = []
    for entry_id in entry_ids:
        entry = get_entry_by_id(index, entry_id)
        if not entry:
            continue
        matches.append({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'exact_sha1',
            'score': 9999,
            'reason': 'exact_sha1_match',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        })
    if matches:
        return matches
    return []

def find_by_build_id_cached(target_build_id, index):
    """Build ID lookup via cached index - O(1) instead of O(N) readelf calls"""
    matches = []
    target = target_build_id.lower()
    seen = set()

    exact_ids = index.get("by_build_id", {}).get(target, [])
    if isinstance(exact_ids, str):
        exact_ids = [exact_ids]

    for entry_id in exact_ids:
        entry = get_entry_by_id(index, entry_id)
        if not entry:
            continue
        seen.add(entry_id)
        matches.append({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'exact',
            'score': 5000,
            'reason': 'exact_build_id_match',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        })

    partial_ids = index.get("by_build_id_prefix", {}).get(target[:16], [])
    if isinstance(partial_ids, str):
        partial_ids = [partial_ids]

    for entry_id in partial_ids:
        if entry_id in seen:
            continue
        entry = get_entry_by_id(index, entry_id)
        if not entry:
            continue
        cached_bid = entry.get("build_id", "")
        matches.append({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'partial',
            'score': 3000,
            'reason': f'partial_build_id_match ({cached_bid[:24]}...)',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        })
    return matches

def find_by_version_cached(version_info, index, target_arch):
    """Version-based lookup using cached index - no filesystem scan needed"""
    target_glibc = None
    for ver in version_info:
        if ver.startswith('likely_glibc_'):
            target_glibc = ver.replace('likely_glibc_', '')
            break
    if not target_glibc:
        for ver in version_info:
            if ver.startswith('required_glibc_'):
                target_glibc = ver.replace('required_glibc_', '')
                break
    if not target_glibc:
        for ver in version_info:
            if ver.startswith('max_glibc_'):
                target_glibc = ver.replace('max_glibc_', '')
                break

    target_ubuntu = None
    for ver in version_info:
        if ver.startswith('ubuntu_') and 'inferred' not in ver:
            target_ubuntu = ver.replace('ubuntu_', '')
            break
    if not target_ubuntu:
        for ver in version_info:
            if ver.startswith('ubuntu_') and 'inferred' in ver:
                match = re.search(r'ubuntu_([0-9.]+)', ver)
                if match:
                    target_ubuntu = match.group(1)
                    break
    target_debian = None
    for ver in version_info:
        if ver.startswith('debian_') and 'inferred' not in ver:
            target_debian = ver.replace('debian_', '')
            break
    if not target_debian:
        for ver in version_info:
            if ver.startswith('debian_') and 'inferred' in ver:
                match = re.search(r'debian_([A-Za-z0-9.]+)', ver)
                if match:
                    target_debian = match.group(1)
                    break

    log.info(
        f"目标 GLIBC: {stderr_version(target_glibc or 'unknown')}, "
        f"目标发行版: {stderr_version(('Debian ' + target_debian) if target_debian else (('Ubuntu ' + target_ubuntu) if target_ubuntu else 'unknown'))}, "
        f"目标架构: {stderr_name(target_arch)}"
    )

    candidate_ids = set()
    if target_glibc:
        version_arch_index = index.get("by_version_arch", {})
        for file_ver in index.get("versions_sorted", []):
            if file_ver == target_glibc or file_ver.startswith(target_glibc + '.') or target_glibc.startswith(file_ver + '.'):
                arch_bucket = version_arch_index.get(file_ver, {})
                if target_arch != 'unknown':
                    candidate_ids.update(arch_bucket.get(target_arch, []))
                    candidate_ids.update(arch_bucket.get('unknown', []))
                else:
                    for ids in arch_bucket.values():
                        candidate_ids.update(ids)

    if not candidate_ids:
        if target_arch != 'unknown':
            candidate_ids.update(index.get('by_arch', {}).get(target_arch, []))
            candidate_ids.update(index.get('by_arch', {}).get('unknown', []))
        else:
            candidate_ids.update(index.get('by_id', {}).keys())

    matches = []
    for entry_id in sorted(candidate_ids):
        entry = get_entry_by_id(index, entry_id)
        if not entry:
            continue
        entry_arch = entry.get('arch', 'unknown')
        if target_arch != 'unknown' and entry_arch != 'unknown' and entry_arch != target_arch:
            continue

        score = 0
        match_reason = []
        score += 100
        match_reason.append("potential_match")
        version_match_rank = 0

        file_ver = entry.get('version')
        sym_count = symbol_count(entry)
        if file_ver and target_glibc:
            if file_ver == target_glibc:
                score += 200
                version_match_rank = 3
                match_reason.append(f"exact_glibc_{file_ver}")
            elif file_ver.startswith(target_glibc + '.'):
                score += 150
                version_match_rank = 2
                match_reason.append(f"prefix_glibc_{file_ver}")
            elif target_glibc.startswith(file_ver + '.'):
                score += 50
                version_match_rank = 1
                match_reason.append(f"parent_glibc_{file_ver}")

        distro_score = 0
        if target_ubuntu:
            ubuntu_tag = target_ubuntu.replace('.', '')
            entry_id = entry.get('id', '')
            if ubuntu_tag in entry_id:
                score += 30
                match_reason.append(f"ubuntu_{target_ubuntu}")
        if target_debian:
            entry_id = entry.get('id', '')
            entry_info = entry.get('info', '')
            debian_version_tag = f'+deb{target_debian}'
            debian_codename = normalize_debian_release(target_debian)
            if debian_version_tag in entry_id or 'debian' in entry_info.lower():
                score += 30
                match_reason.append(f"debian_{target_debian}")
            elif debian_codename and debian_codename in entry_id:
                score += 30
                match_reason.append(f"debian_{debian_codename}")

        if sym_count:
            score += 10
            match_reason.append(f"symbols_{sym_count}")

        distro_score = preferred_distro_package_score(
            entry.get('id', ''),
            entry.get('info', ''),
            target_ubuntu=target_ubuntu,
            target_debian=target_debian,
        )
        if distro_score:
            score += distro_score
            if distro_score > 0:
                match_reason.append(
                    f"{'ubuntu' if target_ubuntu else 'debian'}_preferred"
                )
            else:
                match_reason.append(
                    f"{'debian' if target_ubuntu else 'ubuntu'}_preferred"
                )

        if score > 100:
            name = os.path.basename(entry['path'])
            matches.append({
                'path': entry['path'],
                'name': name,
                'match_type': 'version',
                'score': score,
                'reason': ', '.join(match_reason),
                'glibc_ver': file_ver or 'unknown',
                'arch': entry_arch,
                'info': entry.get('info', ''),
                'symbol_count': sym_count,
                'version_match_rank': version_match_rank,
                'distro_score': distro_score,
                'arch_score': preferred_arch_package_score(name, target_arch),
            })

    matches.sort(key=lambda x: libc_candidate_sort_key(x, target_arch), reverse=True)
    return matches

def find_by_symbol_address(elf_path, index, target_arch=None):
    """
    Use libc_find-style matching: extract symbol addresses from the ELF
    and find libc entries whose .symbols files have matching last 3 hex digits.
    """
    try:
        with context.local(log_level='error'):
            elf = ELF(elf_path, checksec=False)
    except:
        return []

    if target_arch is None:
        target_arch = get_elf_arch(elf_path)
    symbol_constraints = []
    for sym_name in COMMON_LIBC_SYMBOLS:
        try:
            addr = elf.symbols.get(sym_name)
            if addr and addr != 0:
                addr_hex = format(addr, 'x')
                last3 = addr_hex[-3:].lower()
                symbol_constraints.append((sym_name, last3))
        except:
            pass

    if len(symbol_constraints) < 1:
        return []

    symbol_index = index.get("by_symbol_suffix", {})
    candidates = None
    for sym_name, last3 in symbol_constraints:
        matched_ids = set(symbol_index.get(sym_name, {}).get(last3, []))
        if target_arch != 'unknown':
            matched_ids = {
                entry_id for entry_id in matched_ids
                if (get_entry_by_id(index, entry_id) or {}).get('arch') in ('unknown', target_arch)
            }

        if candidates is None:
            candidates = matched_ids
        else:
            candidates &= matched_ids

        if not candidates:
            break

    if not candidates:
        return []

    matches = []
    for entry_id in sorted(candidates):
        entry = get_entry_by_id(index, entry_id)
        if not entry:
            continue
        name = os.path.basename(entry['path'])
        matches.append({
            'path': entry['path'],
            'name': name,
            'match_type': 'symbol_address',
            'score': 4000,
            'reason': f'symbol_address_match ({len(symbol_constraints)} symbols)',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
            'matched_symbol_count': len(symbol_constraints),
            'arch_score': preferred_arch_package_score(name, target_arch),
        })

    return matches

def auto_find_libc(elf_path, candidate_limit=20, group_variants=True):
    index = ensure_index_cache()
    if not index:
        return []

    log.info(f"分析文件: {stderr_path(elf_path)}")
    build_id, arch = inspect_elf_metadata(elf_path)
    log.info(f"架构: {stderr_name(arch)}")

    # Strategy 1: SHA1 exact match (fastest)
    file_sha1 = sha1_of_file(elf_path)
    sha1_matches = find_by_sha1(file_sha1, index)
    if sha1_matches:
        log.success(f"SHA1 精确匹配: {stderr_name(sha1_matches[0]['name'])}")
        return sha1_matches

    # Strategy 2: Build ID match via cache
    all_matches = []

    if not should_try_build_id_match(elf_path):
        build_id = None

    if build_id:
        log.success(f"Build ID: {stderr_hash(build_id)}")
        bid_matches = find_by_build_id_cached(build_id, index)
        if bid_matches:
            log.success(f"通过 Build ID 找到 {stderr_number(len(bid_matches))} 个匹配:")
            for m in bid_matches[:3]:
                match_type = "精确" if m['match_type'] == 'exact' else "部分"
                log.info(f"  [{stderr_choice(match_type)}] {stderr_name(m['name'])}")
                log.info(f"      路径: {stderr_path(m['path'])}")
            all_matches.extend(bid_matches)

    sym_matches = find_by_symbol_address(elf_path, index, arch)
    if sym_matches:
        log.success(f"通过符号地址找到 {stderr_number(len(sym_matches))} 个匹配:")
        for m in sym_matches[:3]:
            log.info(f"  {stderr_name(m['name'])} (GLIBC {stderr_version(m['glibc_ver'])})")
        all_matches.extend(sym_matches)

    # Strategy 4: Version-based matching
    versions = get_glibc_version_from_elf(elf_path)
    if versions:
        log.success("检测到版本信息:")
        for v in sorted(versions):
            log.info(f"  - {stderr_version(v)}")

    ver_matches = find_by_version_cached(versions, index, arch)
    if ver_matches:
        all_matches.extend(ver_matches)

    if not all_matches:
        log.error("未找到匹配的 libc")
        return []

    unique_matches = merge_duplicate_matches(all_matches)
    unique_matches.sort(key=lambda m: m.get('path', ''))
    unique_matches.sort(
        key=lambda m: libc_candidate_sort_key(m, arch),
        reverse=True,
    )
    if group_variants:
        ranked_matches = deduplicate_candidates(unique_matches)
    else:
        ranked_matches = unique_matches

    visible_matches = truncate_candidates(ranked_matches, candidate_limit)
    log.success(
        f"找到 {stderr_number(len(ranked_matches))} 个候选 libc（按匹配度排序）"
        + (
            f"，当前显示 {stderr_number(len(visible_matches))} 个"
            if len(visible_matches) != len(ranked_matches) else ""
        )
        + ":"
    )
    for i, m in enumerate(visible_matches):
        log.info(f"[{stderr_choice(i)}] {stderr_name(m['name'])}")
        log.info(
            f"    匹配度: {stderr_number(m.get('score', 'N/A'))}, "
            f"原因: {stderr_style(m.get('reason', m.get('match_type', '')), 'yellow')}"
        )
        log.info(f"    GLIBC: {stderr_version(m.get('glibc_ver', 'unknown'))}")
        log.info(f"    信息: {m.get('info', '')}")
        log.info(f"    路径: {stderr_path(m['path'])}")
        if group_variants and m.get('variants', 1) > 1:
            log.info(f"    子版本: {stderr_number(m['variants'])} 个，可使用 {stderr_hint('--all-variants')} 查看全部")
        if i == 0:
            log.info(f"    {stderr_hint('>>> 推荐 <<<')}")

    return visible_matches

def download_and_setup_libc(libc_path, elf_path=None, target_dir=None, extra_needed=None, package_hints=None, extra_packages=None):
    ensure_pwntools_cache_dir()
    libc_dir = None
    primary_error = None
    try:
        libc_dir = libcdb.download_libraries(libc_path)
    except Exception as e:
        primary_error = e
        log.warning(f'主下载链路失败，准备回退到 Ubuntu/Debian 仓库索引: {e}')
    if libc_dir is None or not os.path.exists(libc_dir):
        fallback_dir = download_matching_deb_libc_package(libc_path)
        if fallback_dir:
            libc_dir = fallback_dir
        else:
            if primary_error is not None:
                log.failure(f'libc 库下载失败: {primary_error}')
            else:
                log.failure('libc 库下载失败，请检查网络、仓库镜像或 libc 文件有效性')
            return None
    libc_dir = libc_dir.decode() if isinstance(libc_dir, bytes) else libc_dir
    if not find_unstripped_libc_in_dir(libc_dir):
        unstripped_dir = try_unstrip_cached_libc_dir_from_local_url(libc_path, libc_dir)
        if unstripped_dir:
            libc_dir = unstripped_dir
    target_dir = os.path.abspath(target_dir or (os.getcwd() + '/libc_dir'))
    os.makedirs(target_dir, exist_ok=True)
    has_artifacts = False
    for root, _dirs, files in os.walk(libc_dir):
        if any(is_shared_object_artifact(name) for name in files):
            has_artifacts = True
            break
    if not has_artifacts:
        log.failure('下载的 libc 目录为空')
        return None
    copied_files = copy_shared_object_artifacts(
        libc_dir,
        target_dir,
        overwrite=bool(find_unstripped_libc_in_dir(libc_dir)),
        require_dynamic=True,
    )
    copied_files.extend(copy_runtime_libc(libc_path, target_dir, overwrite=False))
    log.info(f"libc 下载目录 : {stderr_path(libc_dir)}")
    log.info(f"libc 输出目录 : {stderr_path(target_dir)}")
    if copied_files:
        log.info(f"本次新增文件 : {stderr_number(len(copied_files))} 个")
    else:
        log.info("目标目录已存在下载的 libc 文件，本次没有新增复制")
    runtime_libc = os.path.join(target_dir, 'libc.so.6')
    if not os.path.exists(runtime_libc) or not elf_has_dynamic_section(runtime_libc):
        log.failure(f"运行时 libc 不可加载: {stderr_path(runtime_libc)}")
        return None
    unstripped_libc = find_unstripped_libc_in_dir(target_dir)
    debug_symbol_file = find_libc_debug_symbol_file_in_dir(target_dir)
    if unstripped_libc:
        log.success(f"未 strip libc : {stderr_path(unstripped_libc)}")
    elif debug_symbol_file:
        log.success(f"libc debug 符号 : {stderr_path(debug_symbol_file)}")
    else:
        log.warning("未能获得带符号的 libc；普通 libc6 包通常是 stripped，需要可用的 libc6-dbg/libc6-dbgsym 或 debuginfod")
    extra_package_copied = []
    if extra_packages:
        log.info(
            "手动追加包 : " +
            ", ".join(stderr_name(name) for name in normalize_package_name_list(extra_packages))
        )
        extra_package_copied = download_extra_packages(libc_path, target_dir, extra_packages=extra_packages)
    if elf_path or extra_needed:
        if elf_path:
            log.info(f"目标 ELF : {stderr_path(elf_path)}")
        if extra_needed:
            log.info(
                "手动追加依赖 : " +
                ", ".join(stderr_name(name) for name in normalize_soname_list(extra_needed))
            )
        missing_before = get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed)
        if missing_before:
            log.info(
                "额外依赖缺失 : " +
                ", ".join(stderr_name(name) for name in missing_before)
            )
        else:
            log.info("额外依赖检查 : 目标目录中已存在所需库")
        missing_after_packages = get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed)
        extra_copied = download_missing_dependencies(
            libc_path,
            elf_path,
            target_dir,
            missing=missing_after_packages,
            extra_needed=extra_needed,
            package_hints=package_hints,
        )
        still_missing = get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed)
        if still_missing:
            log.warning(
                "额外依赖仍缺失: " +
                ", ".join(stderr_name(name) for name in still_missing)
            )
        elif missing_before:
            if extra_copied:
                log.success(f"额外依赖已补全: {stderr_path(target_dir)}")
            else:
                log.success(f"额外依赖已就绪: {stderr_path(target_dir)}")
        else:
            log.success(f"额外依赖已存在: {stderr_path(target_dir)}")
    elif extra_package_copied:
        log.success(f"额外包已补充: {stderr_path(target_dir)}")

    with open(libc_path, 'rb') as f:
        log.info(f"源 libc sha256 : {stderr_hash(hashlib.sha256(f.read()).hexdigest())}")
    src_strings = cached_file_analysis(libc_path).get('strings', '')
    for line in src_strings.splitlines():
        if 'GNU C Library' in line:
            log.info(f"源 libc string : {stderr_style(line.strip(), 'yellow')}")
            break

    libc_files = []
    for root, dirs, filenames in os.walk(target_dir):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            if fname == 'libc.so.6' or re.search(r'libc-\d+\.\d+\.so$', fname):
                libc_files.append(fpath)

    for fpath in sorted(libc_files):
        with open(fpath, 'rb') as f:
            log.info(
                f"匹配 libc sha256 ({stderr_name(os.path.basename(fpath))}) : "
                f"{stderr_hash(hashlib.sha256(f.read()).hexdigest())}"
            )
        matched_strings = cached_file_analysis(fpath).get('strings', '')
        for line in matched_strings.splitlines():
            if 'GNU C Library' in line:
                log.info(
                    f"匹配 libc string ({stderr_name(os.path.basename(fpath))}) : "
                    f"{stderr_style(line.strip(), 'yellow')}"
                )
                break

    return target_dir

def is_elf_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except:
        return False

def prompt_input(message, marker='> '):
    if message:
        if not message.endswith('\n'):
            message += '\n'
        sys.stdout.write(stdout_style(message, "bold", "blue"))
    sys.stdout.write(stdout_style(marker, "bold", "cyan"))
    sys.stdout.flush()
    line = sys.stdin.readline()
    if line == '':
        raise EOFError
    return line.rstrip('\r\n')

def exit_missing_pwntools():
    message = f"缺少 pwntools，当前功能不可用: {PWN_IMPORT_ERROR}"
    log.failure(message)
    sys.exit(1)

def ensure_pwntools_loaded():
    if PWN_IMPORT_ERROR is not None:
        exit_missing_pwntools()

def normalize_cli_dependency_options(args, parser):
    try:
        extra_needed = normalize_soname_list(getattr(args, 'extra_needed', None))
        extra_packages = normalize_package_name_list(getattr(args, 'extra_package', None))
        package_hints = parse_package_hint_specs(getattr(args, 'package_hint', None))
    except ValueError as e:
        parser.error(str(e))
    return extra_needed, extra_packages, package_hints

def validate_candidate_limit(args, parser):
    candidate_limit = getattr(args, 'candidate_limit', None)
    if candidate_limit is not None and candidate_limit < 0:
        parser.error('--candidate-limit 必须大于等于 0')

def require_existing_file(path, description):
    file_path = os.path.abspath(path)
    if not os.path.exists(file_path):
        log.error(f"{description}不存在: {stderr_path(file_path)}")
        sys.exit(1)
    return file_path

def require_existing_elf(path, description):
    file_path = require_existing_file(path, description)
    if not is_elf_file(file_path):
        log.error(f"{description}不是有效 ELF: {stderr_path(file_path)}")
        sys.exit(1)
    return file_path

def log_patch_completion(target_elf, plan):
    log.success(
        f"Patch 完成: {stderr_path(target_elf)} "
        f"(mode={stderr_choice(plan['mode'])}, loader={stderr_path(plan['loader_path'])})"
    )
    log.info(
        "  interpreter: " + format_patch_transition(
            plan['original_state'].get('interpreter'),
            plan['patched_state'].get('interpreter'),
            formatter=stderr_path,
        )
    )
    log.info(
        "  rpath/runpath: " + format_patch_transition(
            plan['original_state'].get('effective_rpath'),
            plan['patched_state'].get('effective_rpath'),
            formatter=lambda value: stderr_style(value, 'yellow'),
        )
    )

def choose_libc_candidate_for_elf(elf_path, args):
    matches = auto_find_libc(
        elf_path,
        candidate_limit=args.candidate_limit,
        group_variants=not args.all_variants,
    )
    if not matches:
        sys.exit(1)

    selected_match = matches[0]
    if getattr(args, 'yes', False):
        if len(matches) > 1:
            log.info(f"使用 --yes，自动选择推荐 libc: {stderr_name(selected_match['name'])}")
        else:
            log.info(f"使用 --yes，自动确认唯一匹配: {stderr_name(selected_match['name'])}")
        return selected_match['path']

    try:
        if len(matches) > 1:
            choice = prompt_input(
                f"\n请选择要使用的 libc (0-{len(matches)-1})，默认 0，输入 q 退出。"
            ).strip()
        else:
            choice = prompt_input(
                f"\n找到 1 个匹配: {selected_match['name']}。回车确认，或输入 q 退出。"
            ).strip()

        if choice and choice.lower() == 'q':
            log.info("已取消操作")
            return None

        if choice and len(matches) > 1:
            idx = int(choice)
            if 0 <= idx < len(matches):
                selected_match = matches[idx]
            else:
                log.warning(f"索引 {stderr_number(idx)} 超出范围，使用默认推荐")
    except ValueError:
        log.warning("无效输入，使用默认推荐")
    except EOFError:
        log.info("已取消操作")
        return None

    return selected_match['path']

def run_core_info_command(_args, _parser):
    core_path = find_rust_core_binary()
    if core_path:
        log.success(f"Rust core: {stderr_path(core_path)}")
    else:
        log.warning("Rust core 未找到，将使用纯 Python 回退")

def run_doctor_command(_args, _parser):
    report = run_doctor()
    print_doctor_report(report)
    if not report['ok']:
        sys.exit(1)

def run_clear_cache_command(_args, _parser):
    result = clear_libc_tool_cache()
    for path, size in result['removed']:
        log.success(f"已清理缓存: {stderr_path(path)} ({stderr_number(format_bytes(size))})")
    if not result['removed']:
        log.info("没有可清理的缓存")
    else:
        log.success(f"缓存清理完成，释放 {stderr_number(format_bytes(result['bytes']))}")

def run_rebuild_index_command(_args, _parser):
    ensure_pwntools_loaded()
    log.info("重建索引缓存...")
    if not rebuild_index_cache(force=True, quiet=False):
        sys.exit(1)
    log.success("索引缓存已重建")

def run_find_command(args, parser):
    ensure_pwntools_loaded()
    validate_candidate_limit(args, parser)
    target_elf = require_existing_elf(args.elf, '目标 ELF ')
    auto_find_libc(
        target_elf,
        candidate_limit=args.candidate_limit,
        group_variants=not args.all_variants,
    )

def run_download_command(args, parser):
    ensure_pwntools_loaded()
    validate_candidate_limit(args, parser)
    extra_needed, extra_packages, package_hints = normalize_cli_dependency_options(args, parser)

    input_file = os.path.abspath(args.file)
    reference_elf = None
    if args.elf:
        reference_elf = require_existing_elf(args.elf, '指定的目标 ELF ')

    if not os.path.exists(input_file):
        log.error(f"文件不存在: {stderr_path(input_file)}")
        sys.exit(1)

    if is_elf_file(input_file) and not is_libc_family_name(input_file):
        reference_elf = input_file
        log.info("检测到 ELF 文件，开始查找匹配的 libc...")
        libc_path = choose_libc_candidate_for_elf(input_file, args)
        if not libc_path:
            return
    else:
        libc_path = input_file
        reference_elf = reference_elf or resolve_reference_elf_arg(libc_path, None)
        log.info(f"直接从 {stderr_path(libc_path)} 下载 libc 调试信息...")

    target_dir = os.path.abspath(args.output_dir) if args.output_dir else get_download_target_dir(input_file, reference_elf)
    log.info("开始下载 libc 调试信息...")
    prepared_dir = download_and_setup_libc(
        libc_path,
        elf_path=reference_elf,
        target_dir=target_dir,
        extra_needed=extra_needed,
        package_hints=package_hints,
        extra_packages=extra_packages,
    )
    if not prepared_dir:
        sys.exit(1)

def run_patch_command(args, parser):
    validate_candidate_limit(args, parser)
    extra_needed, extra_packages, package_hints = normalize_cli_dependency_options(args, parser)
    target_elf = require_existing_elf(args.elf, '目标 ELF ')

    if args.dir and args.libc:
        parser.error('--dir 不能与 --libc 同时使用')
    if args.dir and extra_packages:
        parser.error('--dir 模式不支持 --extra-package，因为不会触发下载')

    if args.dir:
        patch_dir = os.path.abspath(args.dir)
        if not os.path.isdir(patch_dir):
            log.error(f"运行库目录不存在: {stderr_path(patch_dir)}")
            sys.exit(1)
        try:
            plan = patch_elf_with_runtime_dir(
                target_elf,
                patch_dir,
                mode=args.patch_mode,
                verify=not args.no_verify,
                extra_needed=extra_needed,
            )
        except RuntimeError as e:
            log.failure(str(e))
            sys.exit(1)
        log_patch_completion(target_elf, plan)
        return

    ensure_pwntools_loaded()

    if args.libc:
        libc_path = require_existing_file(args.libc, 'libc 文件')
        log.info(f"使用提供的 libc 文件: {stderr_path(libc_path)}")
        local_runtime = inspect_local_runtime_dir_for_libc(
            libc_path,
            target_elf,
            extra_needed=extra_needed,
        )
        if local_runtime['ok']:
            log.info(f"检测到本地完整运行库，直接 patch: {stderr_path(local_runtime['target_dir'])}")
            try:
                plan = patch_elf_with_runtime_dir(
                    target_elf,
                    local_runtime['target_dir'],
                    mode=args.patch_mode,
                    verify=not args.no_verify,
                    extra_needed=extra_needed,
                )
            except RuntimeError as e:
                log.failure(str(e))
                sys.exit(1)
            log_patch_completion(target_elf, plan)
            return
        log.info(
            "本地运行库不可直接 patch，回退到下载流程: "
            + format_runtime_probe_failure(local_runtime)
        )
    else:
        log.info("检测到 ELF 文件，开始查找匹配的 libc...")
        libc_path = choose_libc_candidate_for_elf(target_elf, args)
        if not libc_path:
            return

    target_dir = os.path.abspath(args.output_dir) if args.output_dir else get_download_target_dir(libc_path, target_elf)
    log.info("开始下载 libc 调试信息...")
    prepared_dir = download_and_setup_libc(
        libc_path,
        elf_path=target_elf,
        target_dir=target_dir,
        extra_needed=extra_needed,
        package_hints=package_hints,
        extra_packages=extra_packages,
    )
    if not prepared_dir:
        sys.exit(1)

    try:
        plan = patch_elf_with_runtime_dir(
            target_elf,
            prepared_dir,
            mode=args.patch_mode,
            verify=not args.no_verify,
            extra_needed=extra_needed,
        )
    except RuntimeError as e:
        log.failure(str(e))
        sys.exit(1)
    log_patch_completion(target_elf, plan)

def run_restore_command(args, _parser):
    target_elf = require_existing_elf(args.elf, '目标 ELF ')
    try:
        restored = restore_patched_elf(target_elf)
    except RuntimeError as e:
        log.failure(str(e))
        sys.exit(1)
    log.success(f"已恢复 ELF: {stderr_path(restored)}")

def add_dependency_args(parser):
    parser.add_argument('--extra-needed', action='append', default=None, help='手动追加要检查/补全的共享库 soname，可重复指定')
    parser.add_argument('--extra-package', action='append', default=None, help='手动追加要下载的 Debian/Ubuntu 包名，可重复指定')
    parser.add_argument('--package-hint', action='append', default=None, help='手动指定 soname 到 Debian/Ubuntu 包名候选映射，例如 libssl.so.1.1=libssl1.1')

def add_candidate_args(parser):
    parser.add_argument('--all-variants', action='store_true', help='显示并可选择所有 libc 子版本，不按家族合并')
    parser.add_argument('--candidate-limit', type=int, default=20, help='候选 libc 显示/可选上限，默认 20，传 0 表示不限制')
    parser.add_argument('--yes', '-y', action='store_true', help='自动选择推荐候选并确认后续提示')

def add_patch_behavior_args(parser):
    parser.add_argument('--patch-mode', choices=('rpath', 'replace-needed'), default='rpath', help='patch 模式，默认 rpath')
    parser.add_argument('--no-verify', action='store_true', help='patch 后不执行 loader --list 验证')

def supported_cli_commands():
    return [
        'find',
        'download',
        'patch',
        'restore',
        'doctor',
        'rebuild-index',
        'clear-cache',
        'core-info',
    ]

def supported_cli_command_aliases():
    return {
        'f': 'find',
        'dl': 'download',
        'dlo': 'download',
        'pt': 'patch',
        'p': 'patch',
        'rs': 'restore',
        'r': 'restore',
        'dr': 'doctor',
        'do': 'doctor',
        'reb': 'rebuild-index',
        'ri': 'rebuild-index',
        'cc': 'clear-cache',
        'ci': 'core-info',
    }

def resolve_cli_command_prefix(argv):
    argv = list(argv or ())
    if not argv:
        return argv
    head = argv[0]
    if not head or head.startswith('-'):
        return argv
    commands = supported_cli_commands()
    aliases = supported_cli_command_aliases()
    if head in commands:
        return argv
    if head in aliases:
        resolved = list(argv)
        resolved[0] = aliases[head]
        return resolved
    matches = [command for command in commands if command.startswith(head)]
    if len(matches) == 1:
        resolved = list(argv)
        resolved[0] = matches[0]
        return resolved
    if not matches:
        return argv
    log.failure(
        "命令前缀有歧义: "
        + f"{stderr_choice(head)} -> "
        + ", ".join(stderr_choice(item) for item in matches)
    )
    sys.exit(1)

def build_cli_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description='自动查找、下载和设置 libc',
        epilog='使用 `libc_tool <command> --help` 查看二级命令的详细选项。',
    )
    subparsers = parser.add_subparsers(dest='command', metavar='command')

    find_parser = subparsers.add_parser('find', help='查找 ELF 的候选 libc')
    find_parser.add_argument('elf', help='目标 ELF 路径')
    add_candidate_args(find_parser)
    find_parser.set_defaults(command_func=run_find_command)

    download_parser = subparsers.add_parser('download', help='下载 libc 运行库或根据 ELF 自动匹配后下载')
    download_parser.add_argument('file', help='libc 文件路径；如果传入 ELF，会先匹配候选 libc 再下载')
    download_parser.add_argument('--elf', dest='elf', default=None, help='显式指定要补全依赖的目标 ELF')
    download_parser.add_argument('--output-dir', default=None, help='指定下载输出目录，默认使用输入文件所在目录下的 libc_dir')
    add_dependency_args(download_parser)
    add_candidate_args(download_parser)
    download_parser.set_defaults(command_func=run_download_command)

    patch_parser = subparsers.add_parser('patch', help='patch 目标 ELF，可自动匹配/下载，或直接使用现有运行库')
    patch_parser.add_argument('elf', help='目标 ELF 路径')
    patch_parser.add_argument('--libc', default=None, help='显式指定 libc.so.6 文件；若同目录已有完整运行库则直接 patch，否则回退到下载')
    patch_parser.add_argument('--dir', default=None, help='直接使用已有运行库目录 patch，不触发下载')
    patch_parser.add_argument('--output-dir', default=None, help='指定下载输出目录，默认使用目标 ELF 同目录下的 libc_dir')
    add_dependency_args(patch_parser)
    add_candidate_args(patch_parser)
    add_patch_behavior_args(patch_parser)
    patch_parser.set_defaults(command_func=run_patch_command)

    restore_parser = subparsers.add_parser('restore', help='从 .bak 恢复被 patch 的 ELF')
    restore_parser.add_argument('elf', help='目标 ELF 路径')
    restore_parser.set_defaults(command_func=run_restore_command)

    doctor_parser = subparsers.add_parser('doctor', help='执行环境自检')
    doctor_parser.set_defaults(command_func=run_doctor_command)

    rebuild_parser = subparsers.add_parser('rebuild-index', help='重建 libc 索引缓存')
    rebuild_parser.set_defaults(command_func=run_rebuild_index_command)

    clear_parser = subparsers.add_parser('clear-cache', help='清理 libc_tool/pwntools 下载缓存和 libc 索引缓存')
    clear_parser.set_defaults(command_func=run_clear_cache_command)

    core_parser = subparsers.add_parser('core-info', help='显示 Rust core 加速后端状态')
    core_parser.set_defaults(command_func=run_core_info_command)

    return parser

def main():
    parser = build_cli_parser()
    if not ORIGINAL_ARGV:
        parser.print_help()
        return
    argv = resolve_cli_command_prefix(ORIGINAL_ARGV)
    args = parser.parse_args(argv)
    command_func = getattr(args, 'command_func', None)
    if command_func is None:
        parser.print_help()
        return
    command_func(args, parser)

if __name__ == "__main__":
    main()
