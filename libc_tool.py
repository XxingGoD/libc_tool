#!/usr/bin/env python3
import os
import re
import json
import gzip
import lzma
import shlex
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
        def local(self, **kwargs):
            old_values = {}
            for key, value in kwargs.items():
                old_values[key] = getattr(self, key, None)
                setattr(self, key, value)
            try:
                yield self
            finally:
                for key, value in old_values.items():
                    setattr(self, key, value)

    class _FallbackLog:
        LEVELS = {
            'debug': 10,
            'info': 20,
            'success': 20,
            'warning': 30,
            'warn': 30,
            'error': 40,
            'failure': 40,
        }
        PREFIXES = {
            'debug': '*',
            'info': '*',
            'success': '+',
            'warning': '!',
            'error': 'x',
            'failure': '-',
        }

        def _emit(self, level_name, message):
            current_level = str(getattr(context, 'log_level', 'info') or 'info').lower()
            current_value = self.LEVELS.get(current_level, 20)
            level_value = self.LEVELS.get(level_name, 20)
            if level_value < current_value:
                return
            prefix = self.PREFIXES.get(level_name, '*')
            sys.stderr.write(f"[{prefix}] {message}\n")

        def debug(self, message):
            self._emit('debug', message)

        def info(self, message):
            self._emit('info', message)

        def warning(self, message):
            self._emit('warning', message)

        def error(self, message):
            self._emit('error', message)

        def failure(self, message):
            self._emit('failure', message)

        def success(self, message):
            self._emit('success', message)

    class _FallbackText:
        pass

    context = _FallbackContext()
    log = _FallbackLog()
    text = _FallbackText()
    ELF = None
    libcdb = None


LIBC_DB_PATH = "/home/starlight/CtfTools/libc-database/db"
LIBC_INDEX_CACHE = "/home/starlight/CtfTools/libc-database/db/.index_cache.json"
DOCKER_TEMPLATE_ROOT = "/home/starlight/CTF/deploy_pwn_template"
LOCAL_DOCKER_TEMPLATE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'deploy_pwn_template')
DOCKER_BUNDLE_DIRNAME = 'bundle'
DOCKER_BUNDLE_CHALLENGE_DIRNAME = 'challenge'
DOCKER_BUNDLE_RUNTIME_DIRNAME = 'runtime'
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
    "24.04": "2.39", "24.10": "2.40", "25.04": "2.41", "25.10": "2.42",
    "26.04": "2.43",
}

UBUNTU_CODENAME_MAP = {
    "16.04": "xenial", "16.10": "yakkety", "17.04": "zesty", "17.10": "artful",
    "18.04": "bionic", "18.10": "cosmic", "19.04": "disco", "19.10": "eoan",
    "20.04": "focal", "20.10": "groovy", "21.04": "hirsute", "21.10": "impish",
    "22.04": "jammy", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic",
    "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing",
    "26.04": "resolute", "26.10": "stonking",
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
DOCKER_MANAGED_LABEL = 'libc_tool.managed'
DOCKER_MANAGED_CONTAINER_PREFIX = 'libc-tool-'
DOCKER_MANAGED_IMAGE_PREFIX = 'libc_tool_docker_'

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

def local_tcp_port_available(port, bind_host='0.0.0.0'):
    try:
        port = int(port)
    except Exception:
        return False, 'invalid port'
    if port < 1 or port > 65535:
        return False, 'port out of range'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((bind_host, port))
        return True, ''
    except OSError as e:
        return False, str(e)
    finally:
        sock.close()

def collect_managed_docker_port_owners():
    owners = {}
    try:
        targets = collect_libc_tool_docker_targets()
    except Exception:
        return owners
    for target in targets:
        display = target.get('display_name') or target.get('container_name') or '<unknown>'
        kind = target.get('kind') or 'docker'
        for field, role in (('host_port', 'service'), ('gdb_port', 'gdb')):
            raw_value = str(target.get(field) or '').strip()
            if not raw_value:
                continue
            for item in raw_value.split(','):
                item = item.strip()
                if not item.isdigit():
                    continue
                owners.setdefault(int(item), []).append({
                    'display_name': display,
                    'kind': kind,
                    'role': role,
                })
    return owners

def describe_managed_port_owner(port, owners):
    records = owners.get(int(port), [])
    if not records:
        return ''
    return '; '.join(
        f"{item['display_name']} ({item['kind']}/{item['role']})"
        for item in records
    )

def scan_available_tcp_ports(start_port, count=8, exclude_ports=None, limit=256):
    exclude_ports = {int(item) for item in (exclude_ports or ())}
    candidates = []
    current = max(1, int(start_port))
    scanned = 0
    while current <= 65535 and scanned < limit and len(candidates) < count:
        scanned += 1
        if current not in exclude_ports:
            ok, _detail = local_tcp_port_available(current)
            if ok:
                candidates.append(current)
        current += 1
    return candidates

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

def distro_from_package_version(package_version):
    text_value = str(package_version or '').lower()
    if 'ubuntu' in text_value:
        return 'ubuntu'
    if '+deb' in text_value:
        return 'debian'
    return None

def release_from_package_version(package_version):
    package_version = str(package_version or '')
    distro = distro_from_package_version(package_version)
    if distro == 'ubuntu':
        glibc_ver = package_version.split('-', 1)[0]
        for ubuntu_ver, mapped_glibc in UBUNTU_GLIBC_MAP.items():
            if mapped_glibc == glibc_ver:
                return ubuntu_ver
        return None
    if distro == 'debian':
        debian_suffix_match = re.search(r'\+deb(\d+)u\d+', package_version)
        if debian_suffix_match:
            return debian_suffix_match.group(1)
        glibc_ver = package_version.split('-', 1)[0]
        for debian_release, mapped_glibc in DEBIAN_GLIBC_MAP.items():
            if debian_release.isdigit() and mapped_glibc == glibc_ver:
                return debian_release
    return None

def normalize_repository_package_url(package_url):
    normalized = re.sub(r'(?<!:)//+', '/', str(package_url or '').strip())
    return normalized or None

def build_repository_metadata_from_package_url(package_url, package_version=None, arch=None):
    package_url = normalize_repository_package_url(package_url)
    if not package_url:
        return {}
    parsed = parse_deb_package_filename(package_url) or {}
    package_version = package_version or parsed.get('version')
    arch = arch or parsed.get('arch')
    distro = distro_from_package_version(package_version)
    release = release_from_package_version(package_version)
    metadata = {
        'package_url': package_url,
        'package_version': package_version,
        'package_filename': os.path.basename(package_url),
        'package_arch': arch,
        'package_distro': distro,
        'package_release': release,
    }
    return metadata

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

def download_candidate_libc_package(candidate):
    if not candidate:
        return None
    package_url = normalize_repository_package_url(candidate.get('package_url'))
    if not package_url:
        return None
    cache_key = hashlib.sha256(f'candidate:{package_url}'.encode()).hexdigest()[:16]
    distro = candidate.get('package_distro')
    release = candidate.get('package_release')
    extracted_dir = download_and_extract_libc_package_with_debug(
        package_url,
        cache_key,
        distro=distro,
        release=release,
    )
    if not extracted_dir:
        return None
    try_unstrip_libc_tree(extracted_dir)
    log.success(f'已通过索引元数据下载 libc: {stderr_path(extracted_dir)}')
    return extracted_dir

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

def infer_download_context_from_candidate(candidate):
    if candidate is None:
        return None
    arch = normalize_deb_arch_name(candidate.get('package_arch') or candidate.get('arch'))
    if arch == 'unknown':
        log.warning("无法识别 libc 架构，跳过额外依赖补全")
        return None
    distro = candidate.get('package_distro')
    release = candidate.get('package_release')
    if distro:
        return distro, release, arch
    libc_path = candidate.get('path')
    if libc_path and os.path.exists(libc_path):
        return infer_download_context_from_libc(libc_path)
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

def download_extra_packages_from_candidate(candidate, target_dir, extra_packages=None):
    packages = normalize_package_name_list(extra_packages)
    if not packages:
        return []

    download_context = infer_download_context_from_candidate(candidate)
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

def download_missing_dependencies_from_candidate(candidate, elf_path, target_dir, missing=None, extra_needed=None, package_hints=None):
    if not elf_path and not extra_needed:
        return []
    missing = list(missing if missing is not None else get_missing_needed_libraries(elf_path, target_dir, extra_needed=extra_needed))
    if not missing:
        return []

    download_context = infer_download_context_from_candidate(candidate)
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

    package_url = find_local_libc_database_url(so_path)
    repository_meta = build_repository_metadata_from_package_url(
        package_url,
        package_version=(
            get_ubuntu_glibc_package_version(so_path)
            or get_debian_glibc_package_version(so_path)
        ),
        arch=normalize_deb_arch_name(arch),
    )
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
        "package_url": repository_meta.get('package_url'),
        "package_version": repository_meta.get('package_version'),
        "package_filename": repository_meta.get('package_filename'),
        "package_arch": repository_meta.get('package_arch'),
        "package_distro": repository_meta.get('package_distro'),
        "package_release": repository_meta.get('package_release'),
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

def attach_entry_metadata_to_match(match, entry):
    enriched = dict(match)
    if not entry:
        return enriched
    for key in (
        'id',
        'package_url',
        'package_version',
        'package_filename',
        'package_arch',
        'package_distro',
        'package_release',
    ):
        if entry.get(key) is not None:
            enriched[key] = entry.get(key)
    return enriched

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

def normalize_ubuntu_release_hint(release):
    release = str(release or '').strip()
    if not release:
        return None
    aliases = {
        "26.04": "26.04",
        "25.10": "25.10",
        "25.04": "25.04",
        "24.10": "24.10",
        "24.04.2": "24.04",
        "24.04": "24.04",
        "23.10": "23.10",
        "23.04": "23.04",
        "22.10": "22.10",
        "22.04.5": "22.04",
        "22.04.4": "22.04",
        "22.04.3": "22.04",
        "22.04": "22.04",
        "22.04-HWE": "22.04",
        "21.10": "21.10",
        "21.04": "21.04",
        "20.10": "20.10",
        "20.04.5": "20.04",
        "20.04.4": "20.04",
        "20.04.3": "20.04",
        "20.04": "20.04",
        "19.10": "19.10",
        "19.04": "19.04",
        "18.04.5": "18.04",
        "18.04.4": "18.04",
        "18.04.3": "18.04",
        "18.04": "18.04",
        "18.04-HWE": "18.04",
        "17.10": "17.10",
        "17.04": "17.04",
        "16.04.5": "16.04",
        "16.04.4": "16.04",
        "16.04": "16.04",
        "16.04-old": "16.04",
        "15.10": "15.10",
        "15.04": "15.04",
        "14.04.5": "14.04",
        "14.04.4": "14.04",
        "14.04": "14.04",
    }
    if release in aliases:
        return aliases[release]
    match = re.match(r'^([0-9]{2}\.[0-9]{2})', release)
    if match:
        return match.group(1)
    return release

def glibc_versions_compatible(lhs, rhs):
    left = str(lhs or '').strip()
    right = str(rhs or '').strip()
    if not left or not right:
        return True
    return (
        left == right
        or left.startswith(right + '.')
        or right.startswith(left + '.')
    )

def extract_target_profile(version_info):
    version_info = set(version_info or ())
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
    target_ubuntu_source = ''
    for ver in sorted(version_info):
        if ver.startswith('ubuntu_') and 'inferred' not in ver:
            target_ubuntu = ver.replace('ubuntu_', '')
            target_ubuntu_source = 'ELF 字符串'
            break
    if not target_ubuntu:
        for ver in sorted(version_info):
            if ver.startswith('ubuntu_') and 'inferred' in ver:
                match = re.search(r'ubuntu_([0-9.]+)', ver)
                if match:
                    target_ubuntu = match.group(1)
                    infer_match = re.search(r'\(([^)]+)\)', ver)
                    target_ubuntu_source = infer_match.group(1) if infer_match else '推断'
                    break

    target_debian = None
    target_debian_source = ''
    for ver in sorted(version_info):
        if ver.startswith('debian_') and 'inferred' not in ver:
            target_debian = ver.replace('debian_', '')
            target_debian_source = 'ELF 字符串'
            break
    if not target_debian:
        for ver in sorted(version_info):
            if ver.startswith('debian_') and 'inferred' in ver:
                match = re.search(r'debian_([A-Za-z0-9.]+)', ver)
                if match:
                    target_debian = match.group(1)
                    infer_match = re.search(r'\(([^)]+)\)', ver)
                    target_debian_source = infer_match.group(1) if infer_match else '推断'
                    break

    ubuntu_release = normalize_ubuntu_release_hint(target_ubuntu)
    debian_release = normalize_debian_release(target_debian) if target_debian else None
    ubuntu_expected_glibc = UBUNTU_GLIBC_MAP.get(ubuntu_release) if ubuntu_release else None
    debian_expected_glibc = DEBIAN_GLIBC_MAP.get(debian_release) if debian_release else None
    ubuntu_conflict = bool(
        target_ubuntu and target_glibc and ubuntu_expected_glibc
        and not glibc_versions_compatible(target_glibc, ubuntu_expected_glibc)
    )
    debian_conflict = bool(
        target_debian and target_glibc and debian_expected_glibc
        and not glibc_versions_compatible(target_glibc, debian_expected_glibc)
    )

    distro_display = 'unknown'
    distro_source = ''
    distro_warning = ''
    if target_debian:
        distro_display = f"Debian {target_debian}"
        distro_source = target_debian_source
        if debian_conflict:
            distro_warning = (
                f"Debian {target_debian} 预期 GLIBC {debian_expected_glibc}，"
                f"与当前 GLIBC {target_glibc} 不一致，已忽略发行版加权"
            )
    elif target_ubuntu:
        distro_display = f"Ubuntu {target_ubuntu}"
        distro_source = target_ubuntu_source
        if ubuntu_conflict:
            distro_warning = (
                f"Ubuntu {target_ubuntu} 预期 GLIBC {ubuntu_expected_glibc}，"
                f"与当前 GLIBC {target_glibc} 不一致，已忽略发行版加权"
            )

    return {
        'target_glibc': target_glibc,
        'target_ubuntu': target_ubuntu,
        'target_ubuntu_release': ubuntu_release,
        'target_ubuntu_source': target_ubuntu_source,
        'target_ubuntu_expected_glibc': ubuntu_expected_glibc,
        'target_ubuntu_conflict': ubuntu_conflict,
        'target_debian': target_debian,
        'target_debian_release': debian_release,
        'target_debian_source': target_debian_source,
        'target_debian_expected_glibc': debian_expected_glibc,
        'target_debian_conflict': debian_conflict,
        'effective_target_ubuntu': target_ubuntu if target_ubuntu and not ubuntu_conflict else None,
        'effective_target_debian': target_debian if target_debian and not debian_conflict else None,
        'distro_display': distro_display,
        'distro_source': distro_source,
        'distro_warning': distro_warning,
    }

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
                    lts_ver = normalize_ubuntu_release_hint(inferred_ubuntu)
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
        matches.append(attach_entry_metadata_to_match({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'exact_sha1',
            'score': 9999,
            'reason': 'exact_sha1_match',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        }, entry))
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
        matches.append(attach_entry_metadata_to_match({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'exact',
            'score': 5000,
            'reason': 'exact_build_id_match',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        }, entry))

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
        matches.append(attach_entry_metadata_to_match({
            'path': entry['path'],
            'name': os.path.basename(entry['path']),
            'match_type': 'partial',
            'score': 3000,
            'reason': f'partial_build_id_match ({cached_bid[:24]}...)',
            'glibc_ver': entry.get('version', 'unknown'),
            'arch': entry.get('arch', 'unknown'),
            'info': entry.get('info', ''),
            'symbol_count': symbol_count(entry),
        }, entry))
    return matches

def find_by_version_cached(version_info, index, target_arch):
    """Version-based lookup using cached index - no filesystem scan needed"""
    profile = extract_target_profile(version_info)
    target_glibc = profile['target_glibc']
    target_ubuntu = profile['effective_target_ubuntu']
    target_debian = profile['effective_target_debian']
    distro_display = profile['distro_display']
    if profile['distro_source']:
        distro_display += f" ({profile['distro_source']})"

    log.info(
        f"目标 GLIBC: {stderr_version(target_glibc or 'unknown')}, "
        f"目标发行版: {stderr_version(distro_display)}, "
        f"目标架构: {stderr_name(target_arch)}"
    )
    if profile['distro_warning']:
        log.warning(profile['distro_warning'])

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
            matches.append(attach_entry_metadata_to_match({
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
            }, entry))

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
        matches.append(attach_entry_metadata_to_match({
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
        }, entry))

    return matches

def auto_find_libc(elf_path, candidate_limit=20, group_variants=True, quiet=False):
    index = ensure_index_cache()
    if not index:
        return []

    if not quiet:
        log.info(f"分析文件: {stderr_path(elf_path)}")
    build_id, arch = inspect_elf_metadata(elf_path)
    if not quiet:
        log.info(f"架构: {stderr_name(arch)}")

    # Strategy 1: SHA1 exact match (fastest)
    file_sha1 = sha1_of_file(elf_path)
    sha1_matches = find_by_sha1(file_sha1, index)
    if sha1_matches:
        if not quiet:
            log.success(f"SHA1 精确匹配: {stderr_name(sha1_matches[0]['name'])}")
        return sha1_matches

    # Strategy 2: Build ID match via cache
    all_matches = []

    if not should_try_build_id_match(elf_path):
        build_id = None

    if build_id:
        if not quiet:
            log.success(f"Build ID: {stderr_hash(build_id)}")
        bid_matches = find_by_build_id_cached(build_id, index)
        if bid_matches:
            if not quiet:
                log.success(f"通过 Build ID 找到 {stderr_number(len(bid_matches))} 个匹配:")
                for m in bid_matches[:3]:
                    match_type = "精确" if m['match_type'] == 'exact' else "部分"
                    log.info(f"  [{stderr_choice(match_type)}] {stderr_name(m['name'])}")
                    log.info(f"      路径: {stderr_path(m['path'])}")
            all_matches.extend(bid_matches)

    sym_matches = find_by_symbol_address(elf_path, index, arch)
    if sym_matches:
        if not quiet:
            log.success(f"通过符号地址找到 {stderr_number(len(sym_matches))} 个匹配:")
            for m in sym_matches[:3]:
                log.info(f"  {stderr_name(m['name'])} (GLIBC {stderr_version(m['glibc_ver'])})")
        all_matches.extend(sym_matches)

    # Strategy 4: Version-based matching
    versions = get_glibc_version_from_elf(elf_path)
    if versions and not quiet:
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
    if not quiet:
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

def download_and_setup_libc(libc_path, elf_path=None, target_dir=None, extra_needed=None, package_hints=None, extra_packages=None, libc_candidate=None):
    ensure_pwntools_cache_dir()
    libc_dir = None
    primary_error = None
    local_libc_available = bool(libc_path and os.path.exists(libc_path))
    if local_libc_available:
        try:
            libc_dir = libcdb.download_libraries(libc_path)
        except Exception as e:
            primary_error = e
            log.warning(f'主下载链路失败，准备回退到 Ubuntu/Debian 仓库索引: {e}')
    if libc_dir is None or not os.path.exists(libc_dir):
        fallback_dir = None
        if libc_candidate:
            fallback_dir = download_candidate_libc_package(libc_candidate)
        if not fallback_dir and local_libc_available:
            fallback_dir = download_matching_deb_libc_package(libc_path)
        if fallback_dir:
            libc_dir = fallback_dir
        else:
            if primary_error is not None:
                log.failure(f'libc 库下载失败: {primary_error}')
            else:
                if libc_candidate and libc_candidate.get('package_url'):
                    log.failure('libc 库下载失败，请检查网络、仓库镜像或索引元数据有效性')
                else:
                    log.failure('libc 库下载失败，请检查网络、仓库镜像或 libc 文件有效性')
            return None
    libc_dir = libc_dir.decode() if isinstance(libc_dir, bytes) else libc_dir
    if local_libc_available and not find_unstripped_libc_in_dir(libc_dir):
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
    if local_libc_available:
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
        if libc_candidate:
            extra_package_copied = download_extra_packages_from_candidate(libc_candidate, target_dir, extra_packages=extra_packages)
        else:
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
        if libc_candidate:
            extra_copied = download_missing_dependencies_from_candidate(
                libc_candidate,
                elf_path,
                target_dir,
                missing=missing_after_packages,
                extra_needed=extra_needed,
                package_hints=package_hints,
            )
        else:
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

_PROMPT_TOOLKIT_UNAVAILABLE = object()

def prompt_toolkit_selector_available():
    if os.environ.get('LIBC_TOOL_DISABLE_TUI') == '1':
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return importlib.util.find_spec('prompt_toolkit') is not None

def truncate_ui_text(text, max_length=96):
    text = str(text or '').replace('\n', ' ').strip()
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return text[:max_length - 3] + '...'

def tui_style(text, fg=None, bg=None, bold=False, dim=False, italic=False, reverse=False):
    codes = []
    if bold:
        codes.append('1')
    if dim:
        codes.append('2')
    if italic:
        codes.append('3')
    if reverse:
        codes.append('7')
    if fg is not None:
        codes.append(f'38;5;{fg}')
    if bg is not None:
        codes.append(f'48;5;{bg}')
    if not codes:
        return str(text)
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"

def tui_kv(label, value, label_color=110, value_color=252, bold_value=False, dim_value=False):
    return (
        f"{tui_style(str(label) + ':', fg=label_color, bold=True)} "
        f"{tui_style(value, fg=value_color, bold=bold_value, dim=dim_value)}"
    )

def render_tui_text_line(line, indent="  ", plain_color=251):
    line = str(line or '')
    if not line:
        return ''
    if '\x1b[' in line:
        return f"{indent}{line}"
    return f"{indent}{tui_style(line, fg=plain_color)}"

def selector_window_bounds(total_count, selected_index, window_size):
    if total_count <= window_size:
        return 0, total_count
    half = window_size // 2
    start = max(0, selected_index - half)
    end = start + window_size
    if end > total_count:
        end = total_count
        start = end - window_size
    return start, end

def try_prompt_toolkit_selector(title, subtitle, entries, detail_title='详情', context_lines=None):
    if not entries:
        return None
    if not prompt_toolkit_selector_available():
        return _PROMPT_TOOLKIT_UNAVAILABLE
    try:
        from prompt_toolkit.application import Application
        from prompt_toolkit.formatted_text import ANSI
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import Layout
        from prompt_toolkit.layout.containers import Window
        from prompt_toolkit.layout.controls import FormattedTextControl
    except Exception as e:
        log.debug(f"prompt_toolkit 不可用，回退到文本选择: {e}")
        return _PROMPT_TOOLKIT_UNAVAILABLE

    state = {
        'selected_index': 0,
        'result_index': None,
    }
    max_visible_items = 10

    def render_text():
        selected_index = state['selected_index']
        selected_entry = entries[selected_index]
        start, end = selector_window_bounds(len(entries), selected_index, max_visible_items)
        lines = [
            tui_style(title, fg=183, bold=True),
            "",
            tui_style(subtitle, fg=245),
            "",
        ]
        if context_lines:
            lines.append(tui_style("ELF 信息", fg=81, bold=True))
            for context_line in context_lines:
                lines.append(render_tui_text_line(context_line))
            lines.append("")
        if start > 0:
            lines.append(tui_style("  ...", dim=True))
        for index in range(start, end):
            item = entries[index]
            selected = index == selected_index
            prefix = "❯" if selected else " "
            label = truncate_ui_text(item.get('label', ''), max_length=110)
            if selected:
                line = tui_style(f"{prefix} {label}", fg=255, bold=True, italic=True, reverse=True)
            else:
                line = f"{prefix} {tui_style(label, fg=251, italic=True)}"
            lines.append(line)
        if end < len(entries):
            lines.append(tui_style("  ...", dim=True))
        lines.extend([
            "",
            tui_style(f"{selected_index + 1}/{len(entries)} | Enter 确认 | q 取消", dim=True),
            "",
            tui_style(detail_title, fg=120, bold=True),
        ])
        for detail_line in selected_entry.get('detail_lines', ()):
            lines.append(render_tui_text_line(detail_line))
        return ANSI("\n".join(lines))

    body = Window(
        content=FormattedTextControl(render_text, focusable=True),
        always_hide_cursor=True,
    )
    kb = KeyBindings()

    @kb.add('up')
    @kb.add('k')
    def _move_up(event):
        state['selected_index'] = (state['selected_index'] - 1) % len(entries)
        event.app.invalidate()

    @kb.add('down')
    @kb.add('j')
    def _move_down(event):
        state['selected_index'] = (state['selected_index'] + 1) % len(entries)
        event.app.invalidate()

    @kb.add('pageup')
    def _page_up(event):
        state['selected_index'] = max(0, state['selected_index'] - max_visible_items)
        event.app.invalidate()

    @kb.add('pagedown')
    def _page_down(event):
        state['selected_index'] = min(len(entries) - 1, state['selected_index'] + max_visible_items)
        event.app.invalidate()

    @kb.add('home')
    def _go_home(event):
        state['selected_index'] = 0
        event.app.invalidate()

    @kb.add('end')
    def _go_end(event):
        state['selected_index'] = len(entries) - 1
        event.app.invalidate()

    @kb.add('enter')
    def _accept(event):
        state['result_index'] = state['selected_index']
        event.app.exit()

    @kb.add('q')
    @kb.add('escape')
    @kb.add('c-c')
    def _cancel(event):
        event.app.exit()

    try:
        app = Application(
            layout=Layout(body, focused_element=body),
            key_bindings=kb,
            full_screen=True,
            mouse_support=True,
        )
        app.run()
    except Exception as e:
        log.debug(f"prompt_toolkit 选择器执行失败，回退到文本选择: {e}")
        return _PROMPT_TOOLKIT_UNAVAILABLE

    if state['result_index'] is None:
        return None
    return entries[state['result_index']].get('value')

def build_elf_selector_context_lines(elf_path, matches):
    build_id, arch = inspect_elf_metadata(elf_path)
    profile = extract_target_profile(get_glibc_version_from_elf(elf_path))
    context_lines = [
        tui_kv('ELF', os.path.basename(elf_path), value_color=255, bold_value=True),
        tui_kv('路径', truncate_ui_text(elf_path, max_length=110), value_color=250),
        tui_kv('架构', arch or 'unknown', value_color=229, bold_value=True),
        tui_kv('GLIBC', profile['target_glibc'] or 'unknown', value_color=213, bold_value=True),
        tui_kv('发行版', profile['distro_display'], value_color=222, bold_value=(profile['distro_display'] != 'unknown')),
        tui_kv('来源', profile['distro_source'] or 'unknown', value_color=186, dim_value=(profile['distro_source'] == '')),
        tui_kv('候选数', len(matches), value_color=226, bold_value=True),
    ]
    if build_id:
        context_lines.append(
            tui_kv('Build ID', truncate_ui_text(build_id, max_length=40), value_color=150)
        )
    if profile['distro_warning']:
        context_lines.append(
            tui_kv('状态', profile['distro_warning'], label_color=203, value_color=203, bold_value=True)
        )
    return context_lines

def build_libc_selector_entries(matches):
    entries = []
    for index, match in enumerate(matches):
        reason = match.get('reason', match.get('match_type', ''))
        label = (
            f"[{index}] {match.get('name', '<unknown>')} | "
            f"GLIBC {match.get('glibc_ver', 'unknown')} | "
            f"score {match.get('score', 'N/A')}"
        )
        detail_lines = [
            tui_kv('名称', match.get('name', '<unknown>'), value_color=255, bold_value=True),
            tui_kv('GLIBC', match.get('glibc_ver', 'unknown'), value_color=213, bold_value=True),
            tui_kv('架构', match.get('arch', 'unknown'), value_color=229),
            tui_kv('匹配度', match.get('score', 'N/A'), value_color=226, bold_value=True),
            tui_kv('原因', reason, value_color=186),
        ]
        if match.get('info'):
            detail_lines.append(tui_kv('信息', match['info'], value_color=250))
        if match.get('variants', 1) > 1:
            detail_lines.append(tui_kv('子版本', f"{match['variants']} 个", value_color=222, bold_value=True))
        detail_lines.append(tui_kv('路径', match.get('path', ''), value_color=250))
        entries.append({
            'label': label,
            'detail_lines': detail_lines,
            'value': match,
        })
    return entries

def show_libc_candidates_for_selection(matches):
    sys.stdout.write(stdout_heading("libc 候选\n"))
    for index, match in enumerate(matches):
        sys.stdout.write(
            f"[{index}] {match.get('name', '<unknown>')} "
            f"(GLIBC {match.get('glibc_ver', 'unknown')}, score={match.get('score', 'N/A')})\n"
        )
        if match.get('info'):
            sys.stdout.write(f"    info: {match['info']}\n")
        sys.stdout.write(f"    path: {match.get('path', '')}\n")

def build_docker_selector_entries(targets):
    entries = []
    for index, target in enumerate(targets):
        if target.get('kind') == 'deployment':
            kind_label = '容器'
        elif (target.get('group_size') or 0) > 1:
            kind_label = '镜像组'
        else:
            kind_label = '镜像'
        label_parts = [f"[{index}] {kind_label} {target.get('display_name', '<unknown>')}"]
        if target.get('status'):
            label_parts.append(str(target['status']))
        if target.get('host_port'):
            label_parts.append(f"port={target['host_port']}")
        if target.get('gdb_port'):
            label_parts.append(f"gdb={target['gdb_port']}")
        label = " | ".join(label_parts)
        detail_lines = [
            f"类型: {kind_label}",
            f"名称: {target.get('display_name', '<unknown>')}",
        ]
        if (target.get('group_size') or 0) > 1:
            detail_lines.append(f"镜像层数量: {target['group_size']}")
        if target.get('container_name'):
            detail_lines.append(f"容器名: {target['container_name']}")
        if target.get('status'):
            detail_lines.append(f"状态: {target['status']}")
        if target.get('image_name'):
            detail_lines.append(
                f"镜像: {normalize_docker_image_display_name(target['image_name'])}"
            )
        elif target.get('image_id'):
            detail_lines.append(f"镜像 ID: {target['image_id']}")
        image_items = target.get('image_items') or ()
        if image_items:
            for item in image_items[:6]:
                detail_lines.append(f"层: {(item.get('image_id') or '')[:19]}")
            if len(image_items) > 6:
                detail_lines.append(f"... 其余 {len(image_items) - 6} 层省略")
        if target.get('host_port'):
            detail_lines.append(f"服务端口: {target['host_port']}")
        if target.get('gdb_port'):
            detail_lines.append(f"GDB 端口: {target['gdb_port']}")
        if target.get('elf_path'):
            detail_lines.append(f"ELF: {target['elf_path']}")
        if target.get('deploy_dir'):
            detail_lines.append(f"部署目录: {target['deploy_dir']}")
        entries.append({
            'label': label,
            'detail_lines': detail_lines,
            'value': target,
        })
    return entries

def build_port_selector_entries(port_role_label, requested_port, candidate_ports, owner_map, unavailable_reason):
    entries = []
    for index, port in enumerate(candidate_ports):
        owner_text = describe_managed_port_owner(port, owner_map)
        detail_lines = [
            f"用途: {port_role_label}",
            f"候选端口: {port}",
            "状态: 可用",
        ]
        if unavailable_reason:
            detail_lines.append(f"原端口 {requested_port}: {unavailable_reason}")
        if owner_text:
            detail_lines.append(f"同项目历史占用: {owner_text}")
        entries.append({
            'label': f"[{index}] {port_role_label} -> {port}",
            'detail_lines': detail_lines,
            'value': port,
        })
    return entries

def choose_alternate_host_port(requested_port, port_role_label, auto_yes=False, exclude_ports=None, occupied_reason=None):
    exclude_ports = {int(item) for item in (exclude_ports or ())}
    owner_map = collect_managed_docker_port_owners()
    suggestions = scan_available_tcp_ports(
        max(1, int(requested_port)),
        count=8,
        exclude_ports=exclude_ports,
        limit=512,
    )
    if not suggestions:
        log.error(f"{port_role_label}未找到可用端口，请手动使用 --port/--gdb-port 指定。")
        sys.exit(1)

    reason_text = occupied_reason or f"已被占用，建议改用其他宿主机端口"
    if auto_yes:
        return suggestions[0]

    tui_selected = try_prompt_toolkit_selector(
        f'选择{port_role_label}',
        f'{port_role_label}{requested_port} {reason_text}。上下键选择新端口，Enter 确认，q 取消。',
        build_port_selector_entries(
            port_role_label,
            requested_port,
            suggestions,
            owner_map,
            reason_text,
        ),
        detail_title='端口详情',
    )
    if tui_selected is not _PROMPT_TOOLKIT_UNAVAILABLE:
        if tui_selected is None:
            log.info("已取消启动。")
            sys.exit(0)
        return int(tui_selected)

    sys.stdout.write(stdout_heading(f"{port_role_label}候选端口\n"))
    for index, port in enumerate(suggestions):
        owner_text = describe_managed_port_owner(port, owner_map)
        detail = f"  {owner_text}" if owner_text else ""
        sys.stdout.write(f"[{index}] {port}{detail}\n")
    while True:
        try:
            choice = prompt_input(
                f"\n{port_role_label}{requested_port} {reason_text}。"
                f"请输入新端口，回车使用 {suggestions[0]}，输入 q 取消。"
            ).strip()
        except EOFError:
            log.info("已取消启动。")
            sys.exit(1)
        if not choice:
            return int(suggestions[0])
        if choice.lower() in {'q', 'quit', 'exit'}:
            log.info("已取消启动。")
            sys.exit(0)
        try:
            selected_port = int(choice)
        except ValueError:
            log.warning("请输入有效端口号。")
            continue
        if selected_port < 1 or selected_port > 65535:
            log.warning("端口号必须在 1-65535 之间。")
            continue
        if selected_port in exclude_ports:
            log.warning(f"端口 {selected_port} 与当前 Docker 配置冲突，请重新选择。")
            continue
        ok, detail = local_tcp_port_available(selected_port)
        if not ok:
            log.warning(f"端口 {selected_port} 不可用: {detail}")
            continue
        return selected_port

def resolve_docker_host_ports(service_port, enable_gdbserver=False, gdb_port=None, auto_yes=False):
    selected_service_port = int(service_port)
    selected_gdb_port = int(gdb_port) if gdb_port is not None else 1234

    service_ok, service_detail = local_tcp_port_available(selected_service_port)
    if not service_ok:
        selected_service_port = choose_alternate_host_port(
            selected_service_port,
            '服务端口',
            auto_yes=auto_yes,
            exclude_ports=set(),
            occupied_reason=service_detail,
        )

    if enable_gdbserver:
        gdb_reason = None
        if selected_gdb_port == selected_service_port:
            gdb_reason = '与服务端口冲突'
        else:
            gdb_ok, gdb_detail = local_tcp_port_available(selected_gdb_port)
            if not gdb_ok:
                gdb_reason = gdb_detail
        if gdb_reason:
            selected_gdb_port = choose_alternate_host_port(
                selected_gdb_port,
                'GDB 端口',
                auto_yes=auto_yes,
                exclude_ports={selected_service_port},
                occupied_reason=gdb_reason,
            )

    return selected_service_port, selected_gdb_port

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

def cli_auto_yes(args):
    return bool(getattr(args, 'yes', False))

@contextmanager
def quiet_cli_progress(enabled, level='warning'):
    if enabled:
        with context.local(log_level=level):
            yield
        return
    yield

def log_patch_completion(target_elf, plan, verbose=True):
    log.success(
        f"Patch 完成: {stderr_path(target_elf)} "
        f"(mode={stderr_choice(plan['mode'])}, loader={stderr_path(plan['loader_path'])})"
    )
    if not verbose:
        return
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

def safe_name_fragment(value):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or '').strip()) or 'pwn'

def shell_join_args(args):
    return " ".join(shlex.quote(str(item)) for item in args)

def docker_template_root():
    local_root = os.path.abspath(LOCAL_DOCKER_TEMPLATE_ROOT)
    if os.path.isdir(local_root):
        return local_root
    return os.path.abspath(DOCKER_TEMPLATE_ROOT)

def docker_template_deploy_dir(template_name):
    return os.path.join(docker_template_root(), template_name, 'deploy')

def resolve_docker_template(template_name):
    deploy_dir = docker_template_deploy_dir(template_name)
    if not os.path.isdir(deploy_dir):
        raise RuntimeError(f"Docker 模板不存在: {deploy_dir}")
    return deploy_dir

def default_docker_deploy_dir(elf_path):
    elf_dir = os.path.dirname(os.path.abspath(elf_path))
    elf_name = safe_name_fragment(os.path.basename(elf_path))
    return os.path.join(elf_dir, f'.libc_tool_docker_{elf_name}')

def docker_base_image_for_runtime(runtime_dir, libc_candidate=None, override=None):
    if override:
        return override
    runtime_libc = find_library_artifact(runtime_dir, 'libc.so.6', require_dynamic=True)
    runtime_ubuntu_release = None
    if runtime_libc:
        runtime_ubuntu_release = infer_ubuntu_release_from_libc(runtime_libc)
    if libc_candidate:
        distro = libc_candidate.get('package_distro')
        release = libc_candidate.get('package_release')
        if distro == 'ubuntu' and release:
            return f'ubuntu:{release}'
        if runtime_ubuntu_release:
            return f'ubuntu:{runtime_ubuntu_release}'
        if distro == 'debian':
            codename = normalize_debian_release(release)
            if codename and codename not in {'sid', 'testing'}:
                return f'debian:{codename}'
            return 'debian:stable'
    if runtime_libc:
        if runtime_ubuntu_release:
            return f'ubuntu:{runtime_ubuntu_release}'
        debian_release = normalize_debian_release(infer_debian_release_from_libc(runtime_libc))
        if debian_release and debian_release not in {'sid', 'testing'}:
            return f'debian:{debian_release}'
    return 'ubuntu:20.04'

def docker_compose_program():
    docker_path = shutil.which('docker')
    if docker_path:
        try:
            result = subprocess.run(
                [docker_path, 'compose', 'version'],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:
            result = None
        if result is not None and result.returncode == 0:
            return [docker_path, 'compose']
    docker_compose_path = shutil.which('docker-compose')
    if docker_compose_path:
        return [docker_compose_path]
    raise RuntimeError("未找到 docker compose 或 docker-compose")

def docker_program():
    docker_path = shutil.which('docker')
    if docker_path:
        return docker_path
    raise RuntimeError("未找到 docker")

def run_docker_cli(command, cwd=None, timeout=30):
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except Exception as e:
        raise RuntimeError(f"{shell_join_args(command)} 执行失败: {e}") from e
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        if detail:
            raise RuntimeError(
                f"{shell_join_args(command)} 失败 (exit={result.returncode}): {detail}"
            )
        raise RuntimeError(f"{shell_join_args(command)} 失败 (exit={result.returncode})")
    return result.stdout

def docker_resource_labels(config):
    labels = [(DOCKER_MANAGED_LABEL, '1')]
    if config.get('bundle_name'):
        labels.append(('libc_tool.bundle_name', config['bundle_name']))
    for label_key, config_key in (
        ('libc_tool.host_port', 'host_port'),
        ('libc_tool.gdb_port', 'gdb_port'),
        ('libc_tool.template', 'template_name'),
        ('libc_tool.base_image', 'base_image'),
    ):
        value = config.get(config_key, '')
        if label_key == 'libc_tool.gdb_port' and not config.get('enable_gdbserver'):
            value = ''
        labels.append((label_key, str(value or '')))
    for rel_label, legacy_label, rel_key, host_key in (
        ('libc_tool.elf_rel', 'libc_tool.elf_host', 'elf_path_rel', 'elf_path_host'),
        ('libc_tool.challenge_dir_rel', 'libc_tool.challenge_dir_host', 'challenge_dir_rel', 'challenge_dir_host'),
        ('libc_tool.runtime_dir_rel', 'libc_tool.runtime_dir_host', 'runtime_dir_rel', 'runtime_dir_host'),
    ):
        rel_value = normalize_portable_relpath(config.get(rel_key, ''))
        host_value = str(config.get(host_key, '') or '').strip()
        if rel_value:
            labels.append((rel_label, rel_value))
        elif host_value:
            labels.append((legacy_label, host_value))
    return labels

def docker_repo_name(image_name):
    image_name = str(image_name or '').strip()
    if not image_name:
        return ''
    if ':' in image_name:
        return image_name.rsplit(':', 1)[0]
    return image_name

def is_managed_docker_image_name(image_name):
    return docker_repo_name(image_name).startswith(DOCKER_MANAGED_IMAGE_PREFIX)

def normalize_docker_image_display_name(image_name):
    image_name = str(image_name or '').strip()
    if not image_name:
        return '<none>'
    if image_name.endswith(':latest'):
        return image_name[:-len(':latest')]
    return image_name

def docker_deploy_dir_from_labels(labels):
    labels = labels or {}
    working_dir = labels.get('com.docker.compose.project.working_dir')
    if working_dir:
        return os.path.abspath(working_dir)
    config_files = labels.get('com.docker.compose.project.config_files')
    if config_files:
        first = config_files.split(',', 1)[0].strip()
        if first:
            return os.path.dirname(os.path.abspath(first))
    deploy_dir = labels.get('libc_tool.deploy_dir')
    if deploy_dir:
        return os.path.abspath(deploy_dir)
    return None

def docker_label_path(labels, deploy_dir, rel_key, legacy_key):
    labels = labels or {}
    rel_value = normalize_portable_relpath(labels.get(rel_key) or '')
    if rel_value and deploy_dir:
        return os.path.abspath(os.path.join(deploy_dir, rel_value))
    host_value = str(labels.get(legacy_key) or '').strip()
    if host_value:
        return os.path.abspath(host_value)
    return ''

def docker_host_port_map(container_info):
    port_map = {}
    ports = ((container_info.get('NetworkSettings') or {}).get('Ports') or {})
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        values = []
        for binding in bindings:
            host_port = (binding or {}).get('HostPort')
            if host_port:
                values.append(str(host_port))
        if values:
            port_map[container_port] = ",".join(values)
    return port_map

def sort_ports_for_display(values):
    normalized = []
    for value in values or ():
        value = str(value or '').strip()
        if not value:
            continue
        if value.isdigit():
            normalized.append((0, int(value), value))
        else:
            normalized.append((1, value, value))
    normalized.sort()
    return [item[2] for item in normalized]

def build_grouped_image_target(image_items):
    first = image_items[0]
    deploy_dir = first.get('deploy_dir') or ''
    deploy_name = os.path.basename(os.path.normpath(deploy_dir)) if deploy_dir else ''
    image_ids = [item.get('image_id') or '' for item in image_items if item.get('image_id')]
    image_name = ''
    for item in image_items:
        if item.get('image_name'):
            image_name = item['image_name']
            break
    port_values = sort_ports_for_display({item.get('host_port') for item in image_items if item.get('host_port')})
    gdb_values = sort_ports_for_display({item.get('gdb_port') for item in image_items if item.get('gdb_port')})
    display_name = deploy_name or normalize_docker_image_display_name(image_name or (image_ids[0] if image_ids else '<none>'))
    return {
        'kind': 'image',
        'display_name': display_name,
        'container_id': '',
        'container_name': '',
        'image_id': image_ids[0] if image_ids else '',
        'image_ids': image_ids,
        'image_items': image_items,
        'image_name': image_name,
        'status': 'unused',
        'deploy_dir': deploy_dir,
        'elf_path': first.get('elf_path') or '',
        'challenge_dir': first.get('challenge_dir') or '',
        'runtime_dir': first.get('runtime_dir') or '',
        'host_port': ",".join(port_values),
        'gdb_port': ",".join(gdb_values),
        'group_size': len(image_items),
    }

def order_image_items_for_removal(image_items):
    by_id = {
        item.get('image_id'): item
        for item in image_items
        if item.get('image_id')
    }
    depth_cache = {}

    def depth_for(image_id, seen=None):
        if not image_id:
            return 0
        if image_id in depth_cache:
            return depth_cache[image_id]
        seen = set(seen or ())
        if image_id in seen:
            return 0
        seen.add(image_id)
        item = by_id.get(image_id) or {}
        parent_id = item.get('parent_id') or ''
        depth = 0
        if parent_id in by_id:
            depth = depth_for(parent_id, seen) + 1
        depth_cache[image_id] = depth
        return depth

    return sorted(
        image_items,
        key=lambda item: (
            -depth_for(item.get('image_id') or ''),
            item.get('image_id') or '',
        ),
    )

def remove_image_refs(image_items):
    docker_path = docker_program()
    errors = []
    removed_ids = []
    for item in order_image_items_for_removal(image_items):
        image_ref = item.get('image_name') or item.get('image_id')
        if not image_ref:
            continue
        try:
            run_docker_cli([docker_path, 'image', 'rm', image_ref], timeout=60)
            removed_ids.append(item.get('image_id') or image_ref)
            continue
        except RuntimeError:
            pass
        try:
            run_docker_cli([docker_path, 'image', 'rm', '-f', image_ref], timeout=60)
            removed_ids.append(item.get('image_id') or image_ref)
        except RuntimeError as e:
            errors.append(str(e))
    return {
        'removed_ids': removed_ids,
        'errors': errors,
    }

def collect_libc_tool_docker_targets():
    docker_path = docker_program()
    container_targets = []
    used_image_ids = set()

    raw_container_ids = list(dict.fromkeys(
        run_docker_cli([docker_path, 'ps', '-aq'], timeout=20).split()
    ))
    if raw_container_ids:
        container_items = json.loads(
            run_docker_cli([docker_path, 'inspect'] + raw_container_ids, timeout=60)
        )
        for item in container_items:
            name = str(item.get('Name') or '').lstrip('/')
            labels = ((item.get('Config') or {}).get('Labels') or {})
            managed = (
                labels.get(DOCKER_MANAGED_LABEL) == '1'
                or name.startswith(DOCKER_MANAGED_CONTAINER_PREFIX)
            )
            if not managed:
                continue
            ports = docker_host_port_map(item)
            image_name = (item.get('Config') or {}).get('Image') or ''
            image_id = item.get('Image') or ''
            if image_id:
                used_image_ids.add(image_id)
            deploy_dir = docker_deploy_dir_from_labels(labels)
            container_targets.append({
                'kind': 'deployment',
                'display_name': name or image_name or (item.get('Id') or '')[:12],
                'container_id': item.get('Id') or '',
                'container_name': name,
                'image_id': image_id,
                'image_name': image_name,
                'status': ((item.get('State') or {}).get('Status') or '').strip(),
                'deploy_dir': deploy_dir,
                'bundle_name': labels.get('libc_tool.bundle_name') or '',
                'elf_path': docker_label_path(labels, deploy_dir, 'libc_tool.elf_rel', 'libc_tool.elf_host'),
                'challenge_dir': docker_label_path(labels, deploy_dir, 'libc_tool.challenge_dir_rel', 'libc_tool.challenge_dir_host'),
                'runtime_dir': docker_label_path(labels, deploy_dir, 'libc_tool.runtime_dir_rel', 'libc_tool.runtime_dir_host'),
                'host_port': labels.get('libc_tool.host_port') or ports.get('1337/tcp') or '',
                'gdb_port': labels.get('libc_tool.gdb_port') or ports.get('1234/tcp') or '',
            })

    raw_image_targets = []
    raw_image_ids = list(dict.fromkeys(
        run_docker_cli([docker_path, 'image', 'ls', '-aq'], timeout=20).split()
    ))
    if raw_image_ids:
        image_items = json.loads(
            run_docker_cli([docker_path, 'image', 'inspect'] + raw_image_ids, timeout=60)
        )
        for item in image_items:
            labels = ((item.get('Config') or {}).get('Labels') or {})
            repo_tags = [tag for tag in (item.get('RepoTags') or []) if tag and tag != '<none>:<none>']
            managed_repo_tags = [tag for tag in repo_tags if is_managed_docker_image_name(tag)]
            managed = labels.get(DOCKER_MANAGED_LABEL) == '1' or bool(managed_repo_tags)
            if not managed:
                continue
            image_id = item.get('Id') or ''
            if image_id in used_image_ids:
                continue
            deploy_dir = docker_deploy_dir_from_labels(labels)
            raw_image_targets.append({
                'kind': 'image',
                'display_name': normalize_docker_image_display_name(
                    managed_repo_tags[0] if managed_repo_tags else (repo_tags[0] if repo_tags else image_id[:19])
                ),
                'container_id': '',
                'container_name': '',
                'image_id': image_id,
                'parent_id': item.get('Parent') or '',
                'image_name': managed_repo_tags[0] if managed_repo_tags else (repo_tags[0] if repo_tags else ''),
                'status': 'unused',
                'deploy_dir': deploy_dir,
                'bundle_name': labels.get('libc_tool.bundle_name') or '',
                'elf_path': docker_label_path(labels, deploy_dir, 'libc_tool.elf_rel', 'libc_tool.elf_host'),
                'challenge_dir': docker_label_path(labels, deploy_dir, 'libc_tool.challenge_dir_rel', 'libc_tool.challenge_dir_host'),
                'runtime_dir': docker_label_path(labels, deploy_dir, 'libc_tool.runtime_dir_rel', 'libc_tool.runtime_dir_host'),
                'host_port': labels.get('libc_tool.host_port') or '',
                'gdb_port': labels.get('libc_tool.gdb_port') or '',
            })

    grouped_image_targets = []
    image_groups = {}
    for item in raw_image_targets:
        group_key = (
            item.get('deploy_dir')
            or item.get('bundle_name')
            or item.get('image_name')
            or item.get('image_id')
            or item.get('display_name')
        )
        image_groups.setdefault(group_key, []).append(item)
    for group_items in image_groups.values():
        grouped_image_targets.append(build_grouped_image_target(group_items))

    container_targets.sort(key=lambda item: item['display_name'])
    grouped_image_targets.sort(key=lambda item: item['display_name'])
    return container_targets + grouped_image_targets

def show_libc_tool_docker_targets(targets):
    sys.stdout.write(stdout_heading("libc_tool Docker 资源\n"))
    for index, target in enumerate(targets):
        if target.get('kind') == 'deployment':
            kind_label = 'deployment'
        elif (target.get('group_size') or 0) > 1:
            kind_label = 'image-group'
        else:
            kind_label = 'image'
        summary_parts = []
        if target.get('status'):
            summary_parts.append(target['status'])
        if target.get('host_port'):
            summary_parts.append(f"port={target['host_port']}")
        if target.get('gdb_port'):
            summary_parts.append(f"gdb={target['gdb_port']}")
        if target.get('image_name'):
            summary_parts.append(f"image={normalize_docker_image_display_name(target['image_name'])}")
        if (target.get('group_size') or 0) > 1:
            summary_parts.append(f"layers={target['group_size']}")
        headline = f"[{index}] {kind_label} {target['display_name']}"
        if summary_parts:
            headline += " (" + ", ".join(summary_parts) + ")"
        sys.stdout.write(headline + "\n")
        if target.get('elf_path'):
            sys.stdout.write(f"    elf: {target['elf_path']}\n")
        if target.get('deploy_dir'):
            sys.stdout.write(f"    deploy: {target['deploy_dir']}\n")

def choose_libc_tool_docker_target(targets, auto_yes=False):
    if not targets:
        return None
    if auto_yes:
        if len(targets) == 1:
            return targets[0]
        log.error("--yes 只能在唯一一个 Docker 资源时自动选择；请显式传入 ELF/--deploy-dir，或手动选择。")
        sys.exit(1)
    tui_selected = try_prompt_toolkit_selector(
        '选择 Docker 资源',
        '上下键选择要销毁的容器或镜像，Enter 确认，q 取消。',
        build_docker_selector_entries(targets),
        detail_title='Docker 详情',
    )
    if tui_selected is not _PROMPT_TOOLKIT_UNAVAILABLE:
        if tui_selected is None:
            sys.exit(0)
        return tui_selected
    show_libc_tool_docker_targets(targets)
    while True:
        try:
            choice = prompt_input(
                f"\n请选择要销毁的 Docker 资源 (0-{len(targets)-1})，默认 0，输入 q 取消。"
            ).strip()
        except EOFError:
            log.error("输入结束，已取消销毁。")
            sys.exit(1)
        if not choice:
            return targets[0]
        if choice.lower() in {'q', 'quit', 'exit'}:
            log.info("已取消销毁。")
            sys.exit(0)
        try:
            index = int(choice)
        except ValueError:
            log.warning("请输入有效编号。")
            continue
        if 0 <= index < len(targets):
            selected_target = targets[index]
            log.info(f"已选择 Docker 资源: {stderr_choice(selected_target.get('display_name', '<unknown>'))}")
            return selected_target
        log.warning(f"编号超出范围，请输入 0 到 {len(targets)-1}。")

def destroy_libc_tool_docker_target(target):
    deploy_dir = target.get('deploy_dir')
    compose_file = os.path.join(deploy_dir, 'docker-compose.yaml') if deploy_dir else None
    if compose_file and os.path.exists(compose_file):
        run_docker_compose_action(
            deploy_dir,
            ['down', '--rmi', 'all', '--remove-orphans'],
        )
        post_targets = collect_libc_tool_docker_targets()
        image_group_targets = [
            item for item in post_targets
            if item.get('kind') == 'image' and item.get('deploy_dir') == deploy_dir
        ]
        removal_errors = []
        removed_ids = []
        for image_target in image_group_targets:
            removal = remove_image_refs(image_target.get('image_items') or ())
            removed_ids.extend(removal.get('removed_ids', ()))
            removal_errors.extend(removal.get('errors', ()))
        return {
            'mode': 'compose',
            'deploy_dir': deploy_dir,
            'container_removed': True,
            'image_removed': not removal_errors,
            'image_error': "\n".join(removal_errors),
            'removed_ids': removed_ids,
        }

    if target.get('kind') == 'deployment' and target.get('container_id'):
        docker_path = docker_program()
        run_docker_cli([docker_path, 'rm', '-f', target['container_id']], timeout=60)
    image_items = target.get('image_items') or ()
    if image_items:
        removal = remove_image_refs(image_items)
        image_removed = not removal.get('errors')
        image_error = "\n".join(removal.get('errors', ()))
        removed_ids = removal.get('removed_ids', ())
    else:
        image_ref = target.get('image_name') or target.get('image_id')
        if image_ref:
            removal = remove_image_refs([{
                'image_id': target.get('image_id') or image_ref,
                'image_name': target.get('image_name') or '',
                'parent_id': '',
            }])
            image_removed = not removal.get('errors')
            image_error = "\n".join(removal.get('errors', ()))
            removed_ids = removal.get('removed_ids', ())
        else:
            image_removed = True
            image_error = ''
            removed_ids = ()
    return {
        'mode': 'direct',
        'deploy_dir': deploy_dir,
        'container_removed': target.get('kind') == 'image' or bool(target.get('container_id')),
        'image_removed': image_removed,
        'image_error': image_error,
        'removed_ids': removed_ids,
    }

def yaml_quote(value):
    text_value = str(value)
    return '"' + text_value.replace('\\', '\\\\').replace('"', '\\"') + '"'

def relative_container_path(root_path, file_path, container_root):
    rel_path = os.path.relpath(os.path.abspath(file_path), os.path.abspath(root_path))
    rel_path = rel_path.replace(os.sep, '/')
    return container_root if rel_path == '.' else f"{container_root}/{rel_path}"

def docker_exec_target_path(elf_container_path):
    return f"/tmp/libc_tool_exec_{os.path.basename(elf_container_path)}"

def render_docker_run_script():
    return """#!/bin/bash
set -e

if [ ! -z "$ENABLE_POW" ]
then
    if [ "$ENABLE_POW" == "1" ]
    then
        echo "=================proof-of-work================="
        echo ""
        rand_str=$(head -c 27 /dev/urandom | base64)
        hash_value=$(echo -n "$rand_str" | sha256sum - | cut -c 1-64)
        frontend=$(echo "$rand_str" | cut -c -4 )
        backend=$(echo "$rand_str" | cut -c 5- )
        prompt="sha256(XXXX + \\"${backend}\\") == ${hash_value}"
        echo $prompt
        echo -n "Gime me XXXX: "

        read -t 300 -r input_hash

        if [ "$input_hash" != "$frontend" ]
        then
            echo "Proof of work failed!"
            exit 2
        fi
    fi
fi

unset ENABLE_POW

if [ ! -z "$FLAG" ]
then
    if [ "$(cat /home/ctf/flag)" != "$FLAG" ]
    then
        echo $FLAG > /home/ctf/flag
        chmod 644 /home/ctf/flag
    fi
fi

unset FLAG

launch_script=${LIBC_TOOL_LAUNCH_SCRIPT:-/run_challenge.sh}
gdbserver_enabled=${LIBC_TOOL_GDBSERVER:-0}
gdb_port=${LIBC_TOOL_GDB_PORT:-1234}
gdb_prepare=${LIBC_TOOL_GDB_PREPARE:-}
gdb_target=${LIBC_TOOL_GDB_TARGET:-}

if [ ! -x "$launch_script" ]
then
    echo "launch script not found: $launch_script" >&2
    exit 2
fi

if [ "$gdbserver_enabled" = "1" ]
then
    if [ ! -z "$gdb_prepare" ]
    then
        if [ ! -x "$gdb_prepare" ]
        then
            echo "gdb prepare script not found: $gdb_prepare" >&2
            exit 2
        fi
        "$gdb_prepare"
    fi
    if [ ! -z "$gdb_target" ]
    then
        if [ ! -x "$gdb_target" ]
        then
            echo "gdb target not found: $gdb_target" >&2
            exit 2
        fi
        exec runuser -u ctf --pty -- timeout "${TIMEOUT:-300}" gdbserver --once "0.0.0.0:${gdb_port}" "$gdb_target"
    fi
    exec runuser -u ctf --pty -- timeout "${TIMEOUT:-300}" gdbserver --once "0.0.0.0:${gdb_port}" "$launch_script"
fi

exec runuser -u ctf --pty -- timeout "${TIMEOUT:-300}" "$launch_script"
"""

def render_docker_challenge_script(challenge_dir, command):
    return f"""#!/bin/bash
set -e

challenge_dir={shlex.quote(challenge_dir)}
prepare_script=/prepare_gdb_target.sh

if [ ! -d "$challenge_dir" ]
then
    echo "challenge dir not found: $challenge_dir" >&2
    exit 2
fi

if [ -x "$prepare_script" ]
then
    "$prepare_script"
fi

cd "$challenge_dir"
{command}
"""

def render_docker_gdb_prepare_script(runtime_root, elf_container_path, exec_target_path):
    return f"""#!/bin/bash
set -e

runtime_root={shlex.quote(runtime_root)}
overlay_dir=${{LIBC_TOOL_RUNTIME_OVERLAY:-/tmp/libc_tool_runtime_extra}}
elf_source={shlex.quote(elf_container_path)}
exec_target={shlex.quote(exec_target_path)}

mkdir -p "$overlay_dir"
find "$overlay_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +

cp -f "$elf_source" "$exec_target"
chmod 755 "$exec_target"

if [ ! -d "$runtime_root" ]
then
    exit 0
fi

find "$runtime_root" \\( -type f -o -type l \\) -print0 | while IFS= read -r -d '' lib_path
do
    base=$(basename "$lib_path")
    case "$base" in
        ld.so|ld-linux*|libc.so*|libpthread.so*|libm.so*|libdl.so*|librt.so*|libutil.so*|libnsl.so*|libresolv.so*|libanl.so*|libBrokenLocale.so*|libthread_db.so*|libSegFault.so*|libmemusage.so*|libpcprofile.so*|libcrypt.so*)
            continue
            ;;
    esac
    cp -Lf "$lib_path" "$overlay_dir/$base"
done
"""

def gdb_quote_string(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'

def render_docker_gdb_script(
    elf_bundle_rel,
    runtime_bundle_rel,
    challenge_bundle_rel,
    enable_gdbserver=False,
    gdb_port=1234,
    host_port=None,
    remote_host='127.0.0.1',
    remote_exec_file='/tmp/libc_tool_exec_pwn',
):
    lines = [
        "# generated by libc_tool docker",
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        "set follow-fork-mode parent",
        "set detach-on-fork off",
        "set print thread-events off",
        "python",
        "import os",
        "import gdb",
        "",
        "def _libc_tool_gdb_quote(value):",
        "    return '\"' + str(value).replace('\\\\', '\\\\\\\\').replace('\"', '\\\\\"') + '\"'",
        "",
        "def _libc_tool_run(command):",
        "    try:",
        "        gdb.execute(command)",
        "    except gdb.error as exc:",
        "        gdb.write(f\"libc_tool: {exc}\\n\", gdb.STDERR)",
        "",
        "deploy_dir = os.path.realpath(os.environ.get('LIBC_TOOL_DEPLOY_DIR') or os.getcwd())",
        f"challenge_dir = os.path.join(deploy_dir, {normalize_portable_relpath(challenge_bundle_rel)!r})",
        f"runtime_dir = os.path.join(deploy_dir, {normalize_portable_relpath(runtime_bundle_rel)!r})",
        f"elf_path = os.path.join(deploy_dir, {normalize_portable_relpath(elf_bundle_rel)!r})",
        "sysroot_dir = os.path.join(deploy_dir, '.gdb_sysroot')",
        "solib_search_paths = ':'.join([runtime_dir, challenge_dir])",
        "_libc_tool_run(f'set sysroot {_libc_tool_gdb_quote(sysroot_dir)}')",
        "_libc_tool_run(f'set solib-search-path {_libc_tool_gdb_quote(solib_search_paths)}')",
        "_libc_tool_run(f'set debug-file-directory {_libc_tool_gdb_quote(runtime_dir)}')",
        "_libc_tool_run(f'directory {_libc_tool_gdb_quote(challenge_dir)}')",
        "_libc_tool_run(f'set substitute-path {_libc_tool_gdb_quote(\"/challenge\")} {_libc_tool_gdb_quote(challenge_dir)}')",
        "_libc_tool_run(f'set substitute-path {_libc_tool_gdb_quote(\"/runtime\")} {_libc_tool_gdb_quote(runtime_dir)}')",
        "_libc_tool_run(f'set substitute-path {_libc_tool_gdb_quote(\"/tmp/libc_tool_runtime_extra\")} {_libc_tool_gdb_quote(runtime_dir)}')",
        "_libc_tool_run(f'file {_libc_tool_gdb_quote(elf_path)}')",
        "end",
    ]
    if enable_gdbserver:
        remote_target = f"{remote_host}:{int(gdb_port)}"
        if host_port:
            auto_message = (
                f"libc_tool: gdbserver not ready yet. "
                f"keep one client connected to 127.0.0.1:{int(host_port)}, "
                f"then run libc_tool_remote.\n"
            )
        else:
            auto_message = "libc_tool: gdbserver not ready yet. Run libc_tool_remote later.\n"
        lines.extend([
            f"set remote exec-file {gdb_quote_string(remote_exec_file)}",
            "define libc_tool_remote",
            f"  target remote {remote_target}",
            "end",
            "document libc_tool_remote",
            f"Connect to libc_tool gdbserver at {remote_target}.",
            "end",
            "python",
            "import gdb",
            "try:",
            f"    gdb.execute({('target remote ' + remote_target)!r})",
            "except gdb.error:",
            f"    gdb.write({auto_message!r})",
            "end",
        ])
    else:
        lines.append("# regenerate with --gdbserver if you want target remote preconfigured")
    lines.append("")
    return "\n".join(lines)

def render_docker_gdb_wrapper():
    return """#!/bin/bash
set -e

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export LIBC_TOOL_DEPLOY_DIR="$script_dir"

exec gdb -q -x "$script_dir/debug.gdb" "$@"
"""

def render_dockerfile(base_image, template_name, enable_gdbserver=False):
    header = f"# generated by libc_tool docker, based on {template_name}\n"
    alpine_packages = "socat bash util-linux coreutils shadow"
    debian_packages = "socat bash util-linux coreutils"
    if enable_gdbserver:
        alpine_packages += " gdbserver"
        debian_packages += " gdbserver"
    socat_listen = "tcp-l:1337,reuseaddr" if enable_gdbserver else "tcp-l:1337,reuseaddr,fork"
    socat_exec = "exec:/run_pwn.sh"
    if base_image.startswith('alpine:'):
        return header + f"""FROM {base_image}

USER root

RUN apk update && \\
    apk add --no-cache {alpine_packages} && \\
    if ! id -u ctf >/dev/null 2>&1; then adduser -D -s /bin/sh ctf; fi

WORKDIR /home/ctf

COPY ./flag ./flag
COPY ./run_pwn.sh /
COPY ./run_challenge.sh /
COPY ./prepare_gdb_target.sh /

RUN chmod 644 ./flag && \\
    chmod 755 /run_pwn.sh && \\
    chmod 755 /run_challenge.sh && \\
    chmod 755 /prepare_gdb_target.sh && \\
    chown -R root:root .

EXPOSE 1337

CMD socat {socat_listen} {socat_exec}
"""
    return header + f"""FROM {base_image}

USER root

RUN apt-get update && \\
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {debian_packages} && \\
    rm -rf /var/lib/apt/lists/* && \\
    if ! id -u ctf >/dev/null 2>&1; then useradd -m -s /bin/sh ctf; fi

WORKDIR /home/ctf

COPY ./flag ./flag
COPY ./run_pwn.sh /
COPY ./run_challenge.sh /
COPY ./prepare_gdb_target.sh /

RUN chmod 644 ./flag && \\
    chmod 755 /run_pwn.sh && \\
    chmod 755 /run_challenge.sh && \\
    chmod 755 /prepare_gdb_target.sh && \\
    chown -R root:root .

EXPOSE 1337

CMD socat {socat_listen} {socat_exec}
"""

def render_docker_compose(config):
    resource_labels = docker_resource_labels(config)
    challenge_mount = './' + normalize_portable_relpath(config['challenge_dir_rel'])
    runtime_mount = './' + normalize_portable_relpath(config['runtime_dir_rel'])
    lines = [
        "# docker-compose.yaml generated by libc_tool docker",
        'version: "3"',
        "services:",
        "  pwn:",
        "    build:",
        "      context: .",
        "      labels:",
    ]
    for key, value in resource_labels:
        lines.append(f"        {key}: {yaml_quote(value)}")
    lines.extend([
        f"    container_name: {yaml_quote(config['container_name'])}",
        f"    working_dir: {yaml_quote(config['challenge_root'])}",
        "    restart: unless-stopped",
        "    labels:",
    ])
    for key, value in resource_labels:
        lines.append(f"      {key}: {yaml_quote(value)}")
    lines.extend([
        "    environment:",
        f"      FLAG: {yaml_quote(config['flag'])}",
        f"      ENABLE_POW: {yaml_quote('1' if config['enable_pow'] else '0')}",
        f"      TIMEOUT: {yaml_quote(str(config['timeout']))}",
        f"      LIBC_TOOL_LAUNCH_SCRIPT: {yaml_quote('/run_challenge.sh')}",
        f"      LIBC_TOOL_GDBSERVER: {yaml_quote('1' if config['enable_gdbserver'] else '0')}",
        f"      LIBC_TOOL_GDB_PORT: {yaml_quote(str(config['gdb_port']))}",
        f"      LIBC_TOOL_GDB_PREPARE: {yaml_quote(config['gdb_prepare_script'])}",
        f"      LIBC_TOOL_GDB_TARGET: {yaml_quote(config['gdb_target_path'])}",
        f"      LIBC_TOOL_RUNTIME_OVERLAY: {yaml_quote(config['runtime_overlay_path'])}",
        f"      LD_LIBRARY_PATH: {yaml_quote(config['library_path_env'])}",
        "    ports:",
        f"      - {yaml_quote(str(config['host_port']) + ':1337')}",
        "    volumes:",
        f"      - {yaml_quote(challenge_mount + ':' + config['challenge_root'])}",
        f"      - {yaml_quote(runtime_mount + ':' + config['runtime_root'])}",
    ])
    if config['enable_gdbserver']:
        lines.insert(lines.index("    volumes:"), f"      - {yaml_quote(str(config['gdb_port']) + ':' + str(config['gdb_port']))}")
    lines.append("")
    return "\n".join(lines)

def ensure_runtime_dir_ready_for_execution(elf_path, runtime_dir, extra_needed=None):
    result = inspect_runtime_dir_for_patch(runtime_dir, elf_path, extra_needed=extra_needed)
    if not result['ok']:
        raise RuntimeError(f"运行库目录不可直接执行: {format_runtime_probe_failure(result)}")
    return result

def prepare_runtime_dir_for_docker(args, parser, target_elf, extra_needed, extra_packages, package_hints):
    if args.dir and args.libc:
        parser.error('--dir 不能与 --libc 同时使用')
    if args.dir and extra_packages:
        parser.error('--dir 模式不支持 --extra-package，因为不会触发下载')

    if args.dir:
        runtime_dir = os.path.abspath(args.dir)
        if not os.path.isdir(runtime_dir):
            log.error(f"运行库目录不存在: {stderr_path(runtime_dir)}")
            sys.exit(1)
        ensure_runtime_dir_ready_for_execution(target_elf, runtime_dir, extra_needed=extra_needed)
        return runtime_dir, None, None

    ensure_pwntools_loaded()

    if args.libc:
        libc_candidate = None
        libc_path = require_existing_file(args.libc, 'libc 文件')
        local_runtime = inspect_local_runtime_dir_for_libc(
            libc_path,
            target_elf,
            extra_needed=extra_needed,
        )
        if local_runtime['ok']:
            return local_runtime['target_dir'], libc_path, libc_candidate
    else:
        libc_candidate = choose_libc_candidate_for_elf(target_elf, args)
        if not libc_candidate:
            sys.exit(1)
        libc_path = libc_candidate.get('path')

    output_dir = os.path.abspath(args.output_dir) if args.output_dir else get_download_target_dir(
        libc_path,
        target_elf,
    )
    prepared_dir = download_and_setup_libc(
        libc_path,
        elf_path=target_elf,
        target_dir=output_dir,
        extra_needed=extra_needed,
        package_hints=package_hints,
        extra_packages=extra_packages,
        libc_candidate=libc_candidate,
    )
    if not prepared_dir:
        sys.exit(1)
    ensure_runtime_dir_ready_for_execution(target_elf, prepared_dir, extra_needed=extra_needed)
    return prepared_dir, libc_path, libc_candidate

def write_generated_file(file_path, content, executable=False):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    if executable:
        os.chmod(file_path, 0o755)

def normalize_portable_relpath(path):
    text = str(path or '').strip().replace('\\', '/')
    return text.strip('/')

def docker_bundle_root_host(deploy_dir):
    return os.path.join(os.path.abspath(deploy_dir), DOCKER_BUNDLE_DIRNAME)

def docker_bundle_challenge_host(deploy_dir):
    return os.path.join(
        docker_bundle_root_host(deploy_dir),
        DOCKER_BUNDLE_CHALLENGE_DIRNAME,
    )

def docker_bundle_runtime_host(deploy_dir):
    return os.path.join(
        docker_bundle_root_host(deploy_dir),
        DOCKER_BUNDLE_RUNTIME_DIRNAME,
    )

def reset_generated_path(target_path):
    if os.path.isdir(target_path) and not os.path.islink(target_path):
        shutil.rmtree(target_path)
    elif os.path.lexists(target_path):
        os.unlink(target_path)

def copy_portable_tree(source_dir, target_dir, exclude_paths=None):
    source_dir = os.path.abspath(source_dir)
    target_dir = os.path.abspath(target_dir)
    exclude_paths = {
        os.path.abspath(path)
        for path in (exclude_paths or ())
        if path
    }

    def ignore(current_dir, names):
        ignored = []
        for name in names:
            full_path = os.path.abspath(os.path.join(current_dir, name))
            for excluded in exclude_paths:
                if full_path == excluded or full_path.startswith(excluded + os.sep):
                    ignored.append(name)
                    break
        return ignored

    reset_generated_path(target_dir)
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    shutil.copytree(source_dir, target_dir, ignore=ignore)

def generate_docker_bundle(
    elf_path,
    runtime_dir,
    deploy_dir,
    template_name,
    challenge_dir,
    host_port,
    flag_value,
    enable_pow,
    timeout_seconds,
    base_image,
    container_name,
    enable_gdbserver,
    gdb_port,
):
    resolve_docker_template(template_name)
    runtime_probe = ensure_runtime_dir_ready_for_execution(elf_path, runtime_dir)
    challenge_dir = os.path.abspath(challenge_dir)
    elf_path = os.path.abspath(elf_path)
    runtime_dir = os.path.abspath(runtime_dir)
    deploy_dir = os.path.abspath(deploy_dir)

    try:
        if os.path.commonpath([elf_path, challenge_dir]) != challenge_dir:
            raise ValueError
    except ValueError:
        raise RuntimeError(f"目标 ELF 不在 challenge 目录内: {elf_path} !<= {challenge_dir}")

    runtime_root = '/runtime'
    challenge_root = '/challenge'
    elf_container_path = relative_container_path(challenge_dir, elf_path, challenge_root)
    exec_target_path = docker_exec_target_path(elf_container_path)
    runtime_overlay_path = '/tmp/libc_tool_runtime_extra'
    command = shell_join_args(['exec', exec_target_path])
    elf_rel = os.path.relpath(elf_path, challenge_dir)
    bundle_challenge_rel = normalize_portable_relpath(
        os.path.join(DOCKER_BUNDLE_DIRNAME, DOCKER_BUNDLE_CHALLENGE_DIRNAME)
    )
    bundle_runtime_rel = normalize_portable_relpath(
        os.path.join(DOCKER_BUNDLE_DIRNAME, DOCKER_BUNDLE_RUNTIME_DIRNAME)
    )
    bundle_elf_rel = normalize_portable_relpath(
        os.path.join(DOCKER_BUNDLE_DIRNAME, DOCKER_BUNDLE_CHALLENGE_DIRNAME, elf_rel)
    )
    bundle_challenge_host = docker_bundle_challenge_host(deploy_dir)
    bundle_runtime_host = docker_bundle_runtime_host(deploy_dir)
    config = {
        'container_name': container_name,
        'flag': flag_value,
        'enable_pow': enable_pow,
        'timeout': timeout_seconds,
        'challenge_root': challenge_root,
        'runtime_root': runtime_root,
        'command': command,
        'host_port': host_port,
        'challenge_dir_host': bundle_challenge_host,
        'runtime_dir_host': bundle_runtime_host,
        'deploy_dir_host': '',
        'challenge_dir_rel': bundle_challenge_rel,
        'runtime_dir_rel': bundle_runtime_rel,
        'elf_path_host': '',
        'elf_path_rel': bundle_elf_rel,
        'enable_gdbserver': enable_gdbserver,
        'gdb_port': gdb_port,
        'gdb_prepare_script': '/prepare_gdb_target.sh' if enable_gdbserver else '',
        'gdb_target_path': exec_target_path if enable_gdbserver else '',
        'runtime_overlay_path': runtime_overlay_path,
        'library_path_env': f'{runtime_overlay_path}:{challenge_root}',
        'template_name': template_name,
        'base_image': base_image,
        'bundle_name': os.path.basename(os.path.normpath(deploy_dir)) or container_name,
    }
    os.makedirs(deploy_dir, exist_ok=True)
    os.makedirs(os.path.join(deploy_dir, '.gdb_sysroot'), exist_ok=True)
    copy_portable_tree(
        challenge_dir,
        bundle_challenge_host,
        exclude_paths=[deploy_dir],
    )
    copy_portable_tree(runtime_dir, bundle_runtime_host)
    write_generated_file(
        os.path.join(deploy_dir, 'Dockerfile'),
        render_dockerfile(base_image, template_name, enable_gdbserver=enable_gdbserver),
    )
    write_generated_file(
        os.path.join(deploy_dir, 'docker-compose.yaml'),
        render_docker_compose(config),
    )
    write_generated_file(
        os.path.join(deploy_dir, 'run_pwn.sh'),
        render_docker_run_script(),
        executable=True,
    )
    write_generated_file(
        os.path.join(deploy_dir, 'run_challenge.sh'),
        render_docker_challenge_script(challenge_root, command),
        executable=True,
    )
    write_generated_file(
        os.path.join(deploy_dir, 'prepare_gdb_target.sh'),
        render_docker_gdb_prepare_script(
            runtime_root,
            elf_container_path,
            exec_target_path,
        ),
        executable=True,
    )
    gdb_script_path = os.path.join(deploy_dir, 'debug.gdb')
    write_generated_file(
        gdb_script_path,
        render_docker_gdb_script(
            bundle_elf_rel,
            bundle_runtime_rel,
            bundle_challenge_rel,
            enable_gdbserver=enable_gdbserver,
            gdb_port=gdb_port,
            host_port=host_port,
            remote_exec_file=exec_target_path,
        ),
    )
    gdb_wrapper_path = os.path.join(deploy_dir, 'debug.sh')
    write_generated_file(
        gdb_wrapper_path,
        render_docker_gdb_wrapper(),
        executable=True,
    )
    flag_path = os.path.join(deploy_dir, 'flag')
    if not os.path.exists(flag_path):
        write_generated_file(flag_path, flag_value + '\n')
    return {
        'deploy_dir': deploy_dir,
        'container_name': container_name,
        'command': command,
        'host_port': host_port,
        'runtime_dir': bundle_runtime_host,
        'challenge_dir': bundle_challenge_host,
        'source_runtime_dir': runtime_dir,
        'source_challenge_dir': challenge_dir,
        'base_image': base_image,
        'enable_gdbserver': enable_gdbserver,
        'gdb_port': gdb_port,
        'gdb_script_path': gdb_script_path,
        'gdb_wrapper_path': gdb_wrapper_path,
        'runtime_probe': runtime_probe,
    }

def run_docker_compose_action(deploy_dir, compose_args):
    command = docker_compose_program() + list(compose_args)
    result = subprocess.run(
        command,
        cwd=deploy_dir,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(compose_args)} 失败 (exit={result.returncode})"
        )

def resolve_docker_deploy_dir_for_elf(elf_path, deploy_dir=None):
    if deploy_dir:
        return os.path.abspath(deploy_dir)
    if elf_path:
        return default_docker_deploy_dir(elf_path)
    return None

def run_docker_command(args, parser):
    validate_candidate_limit(args, parser)
    extra_needed, extra_packages, package_hints = normalize_cli_dependency_options(args, parser)
    quiet_yes = cli_auto_yes(args)
    if args.down and args.destroy:
        parser.error('--down 不能与 --destroy 同时使用')
    if (args.down or args.destroy) and args.generate_only:
        parser.error('--generate-only 不能与 --down/--destroy 同时使用')
    if (args.down or args.destroy) and args.no_build:
        parser.error('--no-build 不能与 --down/--destroy 同时使用')

    target_elf = require_existing_elf(args.elf, '目标 ELF ') if args.elf else None
    deploy_dir = resolve_docker_deploy_dir_for_elf(target_elf, args.deploy_dir)

    if args.down:
        if not deploy_dir:
            parser.error('docker --down 需要目标 ELF 或 --deploy-dir')
        if not os.path.isdir(deploy_dir):
            log.error(f"Docker 部署目录不存在: {stderr_path(deploy_dir)}")
            sys.exit(1)
        try:
            run_docker_compose_action(deploy_dir, ['down'])
        except RuntimeError as e:
            log.failure(str(e))
            sys.exit(1)
        log.success(f"Docker 环境已停止: {stderr_path(deploy_dir)}")
        return

    if args.destroy:
        if deploy_dir:
            if not os.path.isdir(deploy_dir):
                log.error(f"Docker 部署目录不存在: {stderr_path(deploy_dir)}")
                sys.exit(1)
            target = {
                'kind': 'deployment',
                'display_name': os.path.basename(os.path.normpath(deploy_dir)) or deploy_dir,
                'container_id': '',
                'container_name': '',
                'image_id': '',
                'image_name': '',
                'status': '',
                'deploy_dir': deploy_dir,
                'elf_path': target_elf or '',
                'challenge_dir': '',
                'runtime_dir': '',
                'host_port': '',
                'gdb_port': '',
            }
        else:
            try:
                targets = collect_libc_tool_docker_targets()
            except RuntimeError as e:
                log.failure(str(e))
                sys.exit(1)
            if not targets:
                log.error("未找到由 libc_tool 构建的 Docker 容器或镜像。")
                sys.exit(1)
            target = choose_libc_tool_docker_target(
                targets,
                auto_yes=quiet_yes,
            )
        try:
            result = destroy_libc_tool_docker_target(target)
        except RuntimeError as e:
            log.failure(str(e))
            sys.exit(1)
        if result.get('image_error'):
            if target.get('kind') == 'image':
                log.failure(f"Docker 镜像删除失败: {result['image_error']}")
                sys.exit(1)
            log.warning(f"容器已删除，但镜像删除失败: {result['image_error']}")
        if target.get('kind') == 'image':
            log.success(
                f"Docker 镜像已销毁: "
                f"{stderr_choice(normalize_docker_image_display_name(target.get('image_name') or target.get('image_id')))}"
            )
        elif result.get('mode') == 'compose':
            log.success(f"Docker 环境和镜像已销毁: {stderr_path(result['deploy_dir'])}")
        else:
            log.success(
                f"Docker 资源已销毁: "
                f"{stderr_choice(target.get('container_name') or target.get('display_name'))}"
            )
        return

    if not target_elf:
        parser.error('docker 生成/启动模式需要目标 ELF')

    with quiet_cli_progress(quiet_yes):
        runtime_dir, _libc_path, libc_candidate = prepare_runtime_dir_for_docker(
            args,
            parser,
            target_elf,
            extra_needed,
            extra_packages,
            package_hints,
        )
    challenge_dir = os.path.abspath(args.challenge_dir) if args.challenge_dir else os.path.dirname(target_elf)
    template_name = args.template
    base_image = docker_base_image_for_runtime(
        runtime_dir,
        libc_candidate=libc_candidate,
        override=args.base_image,
    )
    selected_host_port, selected_gdb_port = resolve_docker_host_ports(
        args.port,
        enable_gdbserver=args.gdbserver,
        gdb_port=args.gdb_port,
        auto_yes=quiet_yes,
    )
    container_name = args.container_name or (
        f"libc-tool-{safe_name_fragment(os.path.basename(target_elf))}-{selected_host_port}"
    )

    try:
        bundle = generate_docker_bundle(
            target_elf,
            runtime_dir,
            deploy_dir,
            template_name,
            challenge_dir,
            selected_host_port,
            args.flag,
            args.enable_pow,
            args.timeout,
            base_image,
            container_name,
            args.gdbserver,
            selected_gdb_port,
        )
    except RuntimeError as e:
        log.failure(str(e))
        sys.exit(1)

    if quiet_yes:
        summary = (
            f"Docker 部署目录已生成: {stderr_path(bundle['deploy_dir'])} "
            f"(port={stderr_number(bundle['host_port'])}"
        )
        if bundle['enable_gdbserver']:
            summary += f", gdb={stderr_number(bundle['gdb_port'])}"
        summary += ")"
        log.success(summary)
    else:
        log.success(
            f"Docker 部署目录已生成: {stderr_path(bundle['deploy_dir'])} "
            f"(base={stderr_choice(bundle['base_image'])}, port={stderr_number(bundle['host_port'])})"
        )
    log.info(f"题目目录挂载: {stderr_path(bundle['challenge_dir'])} -> /challenge")
    log.info(f"运行库目录挂载: {stderr_path(bundle['runtime_dir'])} -> /runtime")
    log.info(f"GDB 脚本已生成: {stderr_path(bundle['gdb_script_path'])}")
    log.info(
        f"使用: {stderr_path(bundle['gdb_wrapper_path'])}"
    )
    if bundle['enable_gdbserver']:
        log.info(f"GDB 调试端口: {stderr_hint('127.0.0.1')}:{stderr_number(bundle['gdb_port'])}")

    if args.generate_only:
        return

    compose_args = ['up', '-d']
    if not args.no_build:
        compose_args.append('--build')
    try:
        run_docker_compose_action(bundle['deploy_dir'], compose_args)
    except RuntimeError as e:
        log.failure(str(e))
        sys.exit(1)

    if quiet_yes:
        summary = (
            f"Docker 环境已启动: {stderr_hint('127.0.0.1')}:{stderr_number(bundle['host_port'])} "
            f"(container={stderr_choice(bundle['container_name'])}"
        )
        if bundle['enable_gdbserver']:
            summary += f", gdb={stderr_hint('127.0.0.1')}:{stderr_number(bundle['gdb_port'])}"
        summary += ")"
        log.success(summary)
        if bundle['enable_gdbserver']:
            log.success(
                f"GDB remote 已就绪: {stderr_hint('target remote')} "
                f"{stderr_hint('127.0.0.1')}:{stderr_number(bundle['gdb_port'])}"
            )
    else:
        log.success(
            f"Docker 环境已启动: {stderr_hint('127.0.0.1')}:{stderr_number(bundle['host_port'])} "
            f"(container={stderr_choice(bundle['container_name'])})"
        )
        if bundle['enable_gdbserver']:
            log.success(
                f"GDB remote 已就绪: {stderr_hint('target remote')} "
                f"{stderr_hint('127.0.0.1')}:{stderr_number(bundle['gdb_port'])}"
            )

def choose_libc_candidate_for_elf(elf_path, args):
    quiet_yes = cli_auto_yes(args)
    prefer_tui = (not quiet_yes) and prompt_toolkit_selector_available()
    matches = auto_find_libc(
        elf_path,
        candidate_limit=args.candidate_limit,
        group_variants=not args.all_variants,
        quiet=prefer_tui or quiet_yes,
    )
    if not matches:
        sys.exit(1)

    selected_match = matches[0]
    if quiet_yes:
        return selected_match

    tui_selected = try_prompt_toolkit_selector(
        '选择 libc 候选',
        (
            '上下键选择候选 libc，Enter 确认，q 取消。'
            if len(matches) > 1 else
            '找到 1 个候选 libc，按 Enter 确认，或按 q 取消。'
        ),
        build_libc_selector_entries(matches),
        detail_title='libc 详情',
        context_lines=build_elf_selector_context_lines(elf_path, matches),
    )
    if tui_selected is not _PROMPT_TOOLKIT_UNAVAILABLE:
        if tui_selected is None:
            return None
        return tui_selected

    if prefer_tui:
        show_libc_candidates_for_selection(matches)

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

    log.info(f"已选择 libc: {stderr_name(selected_match['name'])}")
    return selected_match

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
    quiet_yes = cli_auto_yes(args)

    input_file = os.path.abspath(args.file)
    reference_elf = None
    if args.elf:
        reference_elf = require_existing_elf(args.elf, '指定的目标 ELF ')

    if not os.path.exists(input_file):
        log.error(f"文件不存在: {stderr_path(input_file)}")
        sys.exit(1)

    if is_elf_file(input_file) and not is_libc_family_name(input_file):
        reference_elf = input_file
        if not quiet_yes:
            log.info("检测到 ELF 文件，开始查找匹配的 libc...")
        with quiet_cli_progress(quiet_yes):
            libc_candidate = choose_libc_candidate_for_elf(input_file, args)
        if not libc_candidate:
            return
        libc_path = libc_candidate.get('path')
    else:
        libc_candidate = None
        libc_path = input_file
        reference_elf = reference_elf or resolve_reference_elf_arg(libc_path, None)
        if not quiet_yes:
            log.info(f"直接从 {stderr_path(libc_path)} 下载 libc 调试信息...")

    target_dir = os.path.abspath(args.output_dir) if args.output_dir else get_download_target_dir(input_file, reference_elf)
    if not quiet_yes:
        log.info("开始下载 libc 调试信息...")
    with quiet_cli_progress(quiet_yes):
        prepared_dir = download_and_setup_libc(
            libc_path,
            elf_path=reference_elf,
            target_dir=target_dir,
            extra_needed=extra_needed,
            package_hints=package_hints,
            extra_packages=extra_packages,
            libc_candidate=libc_candidate,
        )
    if not prepared_dir:
        sys.exit(1)
    if quiet_yes:
        log.success(f"libc 已就绪: {stderr_path(prepared_dir)}")

def run_patch_command(args, parser):
    validate_candidate_limit(args, parser)
    extra_needed, extra_packages, package_hints = normalize_cli_dependency_options(args, parser)
    target_elf = require_existing_elf(args.elf, '目标 ELF ')
    quiet_yes = cli_auto_yes(args)

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
            with quiet_cli_progress(quiet_yes):
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
        log_patch_completion(target_elf, plan, verbose=not quiet_yes)
        return

    ensure_pwntools_loaded()

    if args.libc:
        libc_candidate = None
        libc_path = require_existing_file(args.libc, 'libc 文件')
        if not quiet_yes:
            log.info(f"使用提供的 libc 文件: {stderr_path(libc_path)}")
        local_runtime = inspect_local_runtime_dir_for_libc(
            libc_path,
            target_elf,
            extra_needed=extra_needed,
        )
        if local_runtime['ok']:
            if not quiet_yes:
                log.info(f"检测到本地完整运行库，直接 patch: {stderr_path(local_runtime['target_dir'])}")
            try:
                with quiet_cli_progress(quiet_yes):
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
            log_patch_completion(target_elf, plan, verbose=not quiet_yes)
            return
        if not quiet_yes:
            log.info(
                "本地运行库不可直接 patch，回退到下载流程: "
                + format_runtime_probe_failure(local_runtime)
            )
    else:
        if not quiet_yes:
            log.info("检测到 ELF 文件，开始查找匹配的 libc...")
        with quiet_cli_progress(quiet_yes):
            libc_candidate = choose_libc_candidate_for_elf(target_elf, args)
        if not libc_candidate:
            return
        libc_path = libc_candidate.get('path')

    target_dir = os.path.abspath(args.output_dir) if args.output_dir else get_download_target_dir(libc_path, target_elf)
    if not quiet_yes:
        log.info("开始下载 libc 调试信息...")
    with quiet_cli_progress(quiet_yes):
        prepared_dir = download_and_setup_libc(
            libc_path,
            elf_path=target_elf,
            target_dir=target_dir,
            extra_needed=extra_needed,
            package_hints=package_hints,
            extra_packages=extra_packages,
            libc_candidate=libc_candidate,
        )
    if not prepared_dir:
        sys.exit(1)

    try:
        with quiet_cli_progress(quiet_yes):
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
    log_patch_completion(target_elf, plan, verbose=not quiet_yes)

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
    parser.add_argument('--yes', '-y', action='store_true', help='自动选择推荐候选并确认后续提示，同时精简终端输出')

def add_patch_behavior_args(parser):
    parser.add_argument('--patch-mode', choices=('rpath', 'replace-needed'), default='rpath', help='patch 模式，默认 rpath')
    parser.add_argument('--no-verify', action='store_true', help='patch 后不执行 loader --list 验证')

def supported_cli_commands():
    return [
        'find',
        'download',
        'patch',
        'docker',
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
        'dk': 'docker',
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

    docker_parser = subparsers.add_parser('docker', help='为目标 ELF 生成/启动 Docker 调试环境，或管理 libc_tool 创建的 Docker 资源')
    docker_parser.add_argument('elf', nargs='?', help='目标 ELF 路径；在 --down/--destroy 模式下可省略')
    docker_parser.add_argument('--libc', default=None, help='显式指定 libc.so.6 文件；若同目录已有完整运行库则直接使用，否则回退到下载')
    docker_parser.add_argument('--dir', default=None, help='直接使用已有运行库目录生成 Docker 环境，不触发下载')
    docker_parser.add_argument('--output-dir', default=None, help='指定自动下载运行库输出目录，默认使用目标 ELF 同目录下的 libc_dir')
    docker_parser.add_argument('--challenge-dir', default=None, help='挂载到容器内 /challenge 的宿主机目录，默认使用目标 ELF 所在目录')
    docker_parser.add_argument('--deploy-dir', default=None, help='生成 Docker 部署文件的目录，默认使用目标 ELF 同目录下的隐藏目录')
    docker_parser.add_argument('--template', default='ubuntu+socat', help='参考的 deploy 模板名称，默认 ubuntu+socat')
    docker_parser.add_argument('--base-image', default=None, help='显式指定容器基础镜像，例如 ubuntu:22.04')
    docker_parser.add_argument('--container-name', default=None, help='显式指定容器名，默认自动生成')
    docker_parser.add_argument('--port', type=int, default=10001, help='宿主机映射端口，默认 10001')
    docker_parser.add_argument('--gdbserver', action='store_true', help='额外启用 gdbserver 远程调试端口')
    docker_parser.add_argument('--gdb-port', type=int, default=1234, help='宿主机映射的 gdbserver 端口，默认 1234')
    docker_parser.add_argument('--flag', default='flag{this_is_a_real_flag}', help='容器内默认 flag 内容')
    docker_parser.add_argument('--enable-pow', action='store_true', help='启用模板中的 sha256 proof-of-work')
    docker_parser.add_argument('--timeout', type=int, default=300, help='题目进程最大运行秒数，默认 300')
    docker_parser.add_argument('--generate-only', action='store_true', help='只生成 Docker 部署目录，不启动容器')
    docker_parser.add_argument('--no-build', action='store_true', help='启动时不附带 --build')
    docker_parser.add_argument('--down', action='store_true', help='停止并移除该 ELF 对应的 Docker 环境')
    docker_parser.add_argument('--destroy', action='store_true', help='销毁 Docker 环境并删除镜像；未提供 ELF/--deploy-dir 时会列出 libc_tool 创建的容器/镜像供选择')
    add_dependency_args(docker_parser)
    add_candidate_args(docker_parser)
    docker_parser.set_defaults(command_func=run_docker_command)

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
