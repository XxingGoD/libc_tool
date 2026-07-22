#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
keep="${KEEP:-0}"
tmp_root="${TMPDIR:-$repo_root/tests/.tmp}"
mkdir -p "$tmp_root"
workdir="$(mktemp -d "$tmp_root/libc_tool_docker_smoke.XXXXXX")"

cleanup() {
    if [[ "$keep" == "1" ]]; then
        printf 'kept workdir: %s\n' "$workdir"
        return
    fi
    rm -rf "$workdir"
}

trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing command: %s\n' "$1" >&2
        exit 1
    fi
}

require_cmd gcc
require_cmd ldd
require_cmd readelf
require_cmd rg
require_cmd python3

challenge_dir="$workdir/challenge"
runtime_dir="$workdir/libc_dir"
plain_dir="$workdir/deploy_plain"
quiet_dir="$workdir/deploy_quiet"
gdb_dir="$workdir/deploy_gdb"
xinetd_dir="$workdir/deploy_xinetd"
ynetd_dir="$workdir/deploy_ynetd"
binary_path="$challenge_dir/pwn"
quiet_log="$workdir/docker_quiet.log"
plain_port=43001
quiet_port=43011
gdb_service_port=43021
gdb_debug_port=43137
xinetd_port=43031
ynetd_port=43041

mkdir -p "$challenge_dir" "$runtime_dir"

gcc -O2 -fno-stack-protector -no-pie -o "$binary_path" "$script_dir/pwn.c"

loader_path="$(readelf -l "$binary_path" | sed -n 's@.*interpreter: \(.*\)\]@\1@p' | head -n 1)"
libc_path="$(ldd "$binary_path" | sed -n 's@.*libc\.so\.6 => \([^ ]*\) .*@\1@p' | head -n 1)"

if [[ -z "$loader_path" || ! -f "$loader_path" ]]; then
    printf 'failed to resolve loader path\n' >&2
    exit 1
fi

if [[ -z "$libc_path" || ! -f "$libc_path" ]]; then
    printf 'failed to resolve libc path\n' >&2
    exit 1
fi

cp -L "$loader_path" "$runtime_dir/$(basename "$loader_path")"
cp -L "$libc_path" "$runtime_dir/libc.so.6"

python3 "$repo_root/libc_tool.py" docker \
    --dir "$runtime_dir" \
    --deploy-dir "$plain_dir" \
    --port "$plain_port" \
    --generate-only \
    "$binary_path"

for path in \
    "$plain_dir/Dockerfile" \
    "$plain_dir/docker-compose.yaml" \
    "$plain_dir/run_pwn.sh" \
    "$plain_dir/run_challenge.sh" \
    "$plain_dir/prepare_gdb_target.sh" \
    "$plain_dir/debug.gdb" \
    "$plain_dir/debug.sh" \
    "$plain_dir/bundle/challenge/pwn" \
    "$plain_dir/bundle/runtime/libc.so.6" \
    "$plain_dir/flag"
do
    [[ -f "$path" ]]
done

rg -n 'CMD socat tcp-l:1337,reuseaddr,fork exec:/run_pwn\.sh' "$plain_dir/Dockerfile" >/dev/null
rg -n 'chmod 755 /run_pwn\.sh' "$plain_dir/Dockerfile" >/dev/null
rg -n 'chmod 755 /run_challenge\.sh' "$plain_dir/Dockerfile" >/dev/null
rg -n 'exec /tmp/libc_tool_exec_pwn' "$plain_dir/run_challenge.sh" >/dev/null
if rg -n 'exec exec ' "$plain_dir/run_challenge.sh" >/dev/null; then
    printf 'run_challenge.sh unexpectedly contains duplicated exec\n' >&2
    exit 1
fi
if rg -n '/bin/sh -lc' "$plain_dir/run_challenge.sh" >/dev/null; then
    printf 'run_challenge.sh unexpectedly contains sh -lc wrapper\n' >&2
    exit 1
fi
if rg -n -- '--library-path|ld-linux' "$plain_dir/run_challenge.sh" >/dev/null; then
    printf 'run_challenge.sh unexpectedly contains custom loader invocation\n' >&2
    exit 1
fi
rg -n 'LIBC_TOOL_GDBSERVER: "0"' "$plain_dir/docker-compose.yaml" >/dev/null
rg -n 'LIBC_TOOL_LIBRARY_PATH: "/tmp/libc_tool_runtime_extra:/runtime:/challenge"' "$plain_dir/docker-compose.yaml" >/dev/null
if rg -n '^      LD_LIBRARY_PATH:' "$plain_dir/docker-compose.yaml" >/dev/null; then
    printf 'plain compose unexpectedly exports LD_LIBRARY_PATH globally\n' >&2
    exit 1
fi
rg -n 'LIBC_TOOL_GDB_TARGET: ""' "$plain_dir/docker-compose.yaml" >/dev/null
rg -n '\./bundle/challenge:/challenge' "$plain_dir/docker-compose.yaml" >/dev/null
rg -n '\./bundle/runtime:/runtime' "$plain_dir/docker-compose.yaml" >/dev/null
rg -n 'elf_source=/challenge/pwn' "$plain_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'exec_target=/tmp/libc_tool_exec_pwn' "$plain_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'cp -f "\$elf_source" "\$exec_target"' "$plain_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'chmod 755 "\$exec_target"' "$plain_dir/prepare_gdb_target.sh" >/dev/null
rg -n "LIBC_TOOL_DEPLOY_DIR" "$plain_dir/debug.sh" >/dev/null
rg -n 'gdb -q -x "\$script_dir/debug\.gdb"' "$plain_dir/debug.sh" >/dev/null
rg -n "deploy_dir = os\\.path\\.realpath\\(os\\.environ\\.get\\('LIBC_TOOL_DEPLOY_DIR'\\) or os\\.getcwd\\(\\)\\)" "$plain_dir/debug.gdb" >/dev/null
rg -n "bundle/challenge" "$plain_dir/debug.gdb" >/dev/null
rg -n "bundle/runtime" "$plain_dir/debug.gdb" >/dev/null
rg -n 'set solib-search-path ' "$plain_dir/debug.gdb" >/dev/null
rg -n 'set substitute-path ' "$plain_dir/debug.gdb" >/dev/null
if rg -n '^target remote ' "$plain_dir/debug.gdb" >/dev/null; then
    printf 'plain debug.gdb unexpectedly contains target remote\n' >&2
    exit 1
fi
if rg -n 'gdbserver' "$plain_dir/Dockerfile" >/dev/null; then
    printf 'plain Dockerfile unexpectedly contains gdbserver\n' >&2
    exit 1
fi

python3 "$repo_root/libc_tool.py" docker \
    -y \
    --dir "$runtime_dir" \
    --deploy-dir "$quiet_dir" \
    --port "$quiet_port" \
    --generate-only \
    "$binary_path" \
    >"$quiet_log" 2>&1

rg -n 'Docker 部署目录已生成:' "$quiet_log" >/dev/null
rg -n '题目目录挂载:' "$quiet_log" >/dev/null
rg -n '运行库目录挂载:' "$quiet_log" >/dev/null
rg -n 'GDB 脚本已生成:' "$quiet_log" >/dev/null
rg -n '使用: ' "$quiet_log" >/dev/null
if rg -n '使用 --yes|自动选择推荐 libc|自动确认唯一匹配|检测到 ELF 文件，开始查找匹配的 libc|开始下载 libc 调试信息|自动切换到' "$quiet_log" >/dev/null; then
    printf 'quiet docker output unexpectedly contains libc verbose logs\n' >&2
    cat "$quiet_log" >&2
    exit 1
fi

python3 "$repo_root/libc_tool.py" docker \
    --dir "$runtime_dir" \
    --deploy-dir "$gdb_dir" \
    --port "$gdb_service_port" \
    --generate-only \
    --gdbserver \
    --gdb-port "$gdb_debug_port" \
    "$binary_path"

for path in \
    "$gdb_dir/Dockerfile" \
    "$gdb_dir/docker-compose.yaml" \
    "$gdb_dir/run_pwn.sh" \
    "$gdb_dir/run_challenge.sh" \
    "$gdb_dir/prepare_gdb_target.sh" \
    "$gdb_dir/debug.gdb" \
    "$gdb_dir/debug.sh" \
    "$gdb_dir/bundle/challenge/pwn" \
    "$gdb_dir/bundle/runtime/libc.so.6" \
    "$gdb_dir/flag"
do
    [[ -f "$path" ]]
done

rg -n 'gdbserver' "$gdb_dir/Dockerfile" >/dev/null
rg -n 'CMD socat tcp-l:1337,reuseaddr,fork,max-children=1 exec:/run_pwn\.sh' "$gdb_dir/Dockerfile" >/dev/null
rg -n 'chmod 755 /run_pwn\.sh' "$gdb_dir/Dockerfile" >/dev/null
rg -n 'chmod 755 /run_challenge\.sh' "$gdb_dir/Dockerfile" >/dev/null
rg -n "${gdb_debug_port}:${gdb_debug_port}" "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n 'LIBC_TOOL_GDBSERVER: "1"' "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n "LIBC_TOOL_GDB_PORT: \"${gdb_debug_port}\"" "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n 'LIBC_TOOL_GDB_PREPARE: "/prepare_gdb_target\.sh"' "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n 'LIBC_TOOL_GDB_TARGET: "/tmp/libc_tool_exec_pwn"' "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n 'LIBC_TOOL_LIBRARY_PATH: "/tmp/libc_tool_runtime_extra:/runtime:/challenge"' "$gdb_dir/docker-compose.yaml" >/dev/null
if rg -n '^      LD_LIBRARY_PATH:' "$gdb_dir/docker-compose.yaml" >/dev/null; then
    printf 'gdb compose unexpectedly exports LD_LIBRARY_PATH globally\n' >&2
    exit 1
fi
rg -n '\./bundle/challenge:/challenge' "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n '\./bundle/runtime:/runtime' "$gdb_dir/docker-compose.yaml" >/dev/null
rg -n 'gdbserver --once --wrapper env "LD_LIBRARY_PATH=\$\{runtime_library_path\}" --' "$gdb_dir/run_pwn.sh" >/dev/null
rg -n 'elf_source=/challenge/pwn' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'exec_target=/tmp/libc_tool_exec_pwn' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'cp -f "\$elf_source" "\$exec_target"' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'chmod 755 "\$exec_target"' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n 'cp -Lf ' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n '/tmp/libc_tool_runtime_extra' "$gdb_dir/prepare_gdb_target.sh" >/dev/null
rg -n "LIBC_TOOL_DEPLOY_DIR" "$gdb_dir/debug.sh" >/dev/null
rg -n 'bundle_dir = os\.path\.commonpath\(\[challenge_dir, runtime_dir\]\)' "$gdb_dir/debug.gdb" >/dev/null
rg -n "_libc_tool_run\(f'set sysroot" "$gdb_dir/debug.gdb" >/dev/null
if rg -n 'gdb_sysroot' "$gdb_dir/debug.gdb" >/dev/null; then
    printf 'gdb script unexpectedly uses an empty local sysroot directory\n' >&2
    exit 1
fi
rg -n "target remote 127\\.0\\.0\\.1:${gdb_debug_port}" "$gdb_dir/debug.gdb" >/dev/null
rg -n 'LIBC_TOOL_GDB_WAIT' "$gdb_dir/debug.gdb" >/dev/null
rg -n '^set follow-fork-mode parent$' "$gdb_dir/debug.gdb" >/dev/null
rg -n '^set detach-on-fork on$' "$gdb_dir/debug.gdb" >/dev/null
if rg -n '^set detach-on-fork off$' "$gdb_dir/debug.gdb" >/dev/null; then
    printf 'gdb debug.gdb unexpectedly keeps fork children attached\n' >&2
    exit 1
fi
rg -n "gdb.execute\('disconnect', to_string=True\)" "$gdb_dir/debug.gdb" >/dev/null
rg -n "gdb.execute\('sharedlibrary', to_string=True\)" "$gdb_dir/debug.gdb" >/dev/null
rg -n '^define libc_tool_remote$' "$gdb_dir/debug.gdb" >/dev/null
rg -n 'set remote exec-file "/tmp/libc_tool_exec_pwn"' "$gdb_dir/debug.gdb" >/dev/null
rg -n "bundle/challenge" "$gdb_dir/debug.gdb" >/dev/null
rg -n "bundle/runtime" "$gdb_dir/debug.gdb" >/dev/null
rg -n 'set substitute-path ' "$gdb_dir/debug.gdb" >/dev/null
rg -n "keep one client connected to 127\\.0\\.0\\.1:${gdb_service_port}" "$gdb_dir/debug.gdb" >/dev/null
if rg -n '/bin/sh -lc' "$gdb_dir/run_challenge.sh" >/dev/null; then
    printf 'gdb run_challenge.sh unexpectedly contains sh -lc wrapper\n' >&2
    exit 1
fi
if rg -n 'exec exec ' "$gdb_dir/run_challenge.sh" >/dev/null; then
    printf 'gdb run_challenge.sh unexpectedly contains duplicated exec\n' >&2
    exit 1
fi
if rg -n -- '--library-path|ld-linux' "$gdb_dir/run_challenge.sh" >/dev/null; then
    printf 'gdb run_challenge.sh unexpectedly contains custom loader invocation\n' >&2
    exit 1
fi

python3 "$repo_root/libc_tool.py" docker \
    --dir "$runtime_dir" \
    --deploy-dir "$xinetd_dir" \
    --template ubuntu+xinetd+chroot \
    --port "$xinetd_port" \
    --generate-only \
    "$binary_path"

[[ -f "$xinetd_dir/Dockerfile" ]]
[[ -f "$xinetd_dir/ctf.xinetd" ]]
rg -n 'CMD xinetd -f /etc/ctf\.xinetd' "$xinetd_dir/Dockerfile" >/dev/null
rg -n 'COPY ./ctf\.xinetd /etc/ctf\.xinetd' "$xinetd_dir/Dockerfile" >/dev/null

python3 "$repo_root/libc_tool.py" docker \
    --dir "$runtime_dir" \
    --deploy-dir "$ynetd_dir" \
    --template alpine+ynetd+chroot+patchelf2 \
    --port "$ynetd_port" \
    --generate-only \
    "$binary_path"

[[ -f "$ynetd_dir/Dockerfile" ]]
[[ -f "$ynetd_dir/bin/ynetd" ]]
rg -n 'CMD /usr/local/bin/ynetd -p 1337' "$ynetd_dir/Dockerfile" >/dev/null
rg -n 'COPY ./bin/ynetd /usr/local/bin/ynetd' "$ynetd_dir/Dockerfile" >/dev/null

printf 'smoke ok\n'
printf 'binary: %s\n' "$binary_path"
printf 'runtime: %s\n' "$runtime_dir"
printf 'plain deploy: %s\n' "$plain_dir"
printf 'gdb deploy: %s\n' "$gdb_dir"
printf 'xinetd deploy: %s\n' "$xinetd_dir"
printf 'ynetd deploy: %s\n' "$ynetd_dir"
