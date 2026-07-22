# libc_tool

`libc_tool.py` 是个给 PWN / 本地调试用的脚本

- 给 ELF 找可能匹配的 `libc`
- 从已有 `libc.so` 下载整套运行库
- 按目标程序的 `DT_NEEDED` 补缺的共享库
- 按 `soname` 或 Debian/Ubuntu 包名补额外依赖
- 自动校验 `libstdc++.so.6` / `libgcc_s.so.1` 的 ABI 版本需求

## 依赖

- Python 3
- `pwntools`
- `patchelf`（执行 `patch` 时需要）
- `unix_ar` 或系统 `ar`；`data.tar.zst` 还需要 `zstandard`
- `eu-unstrip`（来自 `elfutils`，用于把 `libc6-dbg` / `libc6-dbgsym` 合并成未 strip 的 libc）
- `readelf`、`objdump`、`strings`
- 可选：`docker compose` 或 `docker-compose`，用于一键启动容器调试环境
- 可选：Rust/Cargo，用于构建 `libc_tool_core`
检查：

```bash
python3 libc_tool.py doctor
```

## Rust Core

`libc_tool.py` 仍是入口，Rust core 是可选加速后端。当前迁移到 Rust 的路径：

- ELF 基础解析：build-id、架构、`DT_NEEDED`、是否有 `.dynamic`、是否有 debug section
- `libc-database` 索引构建：sha1、build-id、架构、版本、常用符号 suffix 索引
- `GLIBCXX_*` / `CXXABI_*` / `GCC_*` / `GLIBC_*` / `GLIBC_ABI_*` token 提取
- Debian/Ubuntu `Packages` control entries 扫描和候选包 URL 排序

构建：

```bash
cargo build --release
```

Python 会按以下顺序查找 core：

- 环境变量 `LIBC_TOOL_CORE`
- `libc_tool.py` 同目录下的 `libc_tool_core`
- 仓库内 `target/release/libc_tool_core`
- `PATH` 中的 `libc_tool_core`

查看是否启用：

```bash
python3 libc_tool.py core-info
```

如果找不到 Rust core，工具自动回退到纯 Python 实现。

重建索引时如果 Rust core 可用，会优先走 Rust：

```bash
python3 libc_tool.py rebuild-index
```

## libc-database

这个脚本依赖本地 `libc-database`。官方仓库：

- `https://github.com/niklasb/libc-database`


```bash
git clone https://github.com/niklasb/libc-database.git ./libc-database
cd ./libc-database
./get ubuntu
```

如果要把本地 `libc-database` 也填充 Debian 条目：

```bash
./get debian
```

脚本下载回退和依赖补全会优先使用 `libc` 字符串里的发行版信息，Ubuntu 使用 `archive.ubuntu.com` / `security.ubuntu.com`，Debian 使用 `deb.debian.org` / `security.debian.org` / `archive.debian.org`。需要换源时可设置：

```bash
export PWN_DEBIAN_ARCHIVE_URL=https://deb.debian.org/debian
export PWN_DEBIAN_SECURITY_URL=https://security.debian.org/debian-security
export PWN_DEBIAN_OLD_RELEASES_URL=https://archive.debian.org/debian
export PWN_DEBIAN_OLD_SECURITY_URL=https://archive.debian.org/debian-security
export PWN_DEBIAN_DEBUG_URL=https://deb.debian.org/debian-debug
export PWN_DEBIAN_OLD_DEBUG_URL=https://archive.debian.org/debian-debug
export PWN_UBUNTU_DDEBS_URL=https://ddebs.ubuntu.com
```

数据库和缓存路径支持环境变量，默认会自动发现仓库旁边或 `~/CtfTools` 下的数据库：

```bash
export LIBC_TOOL_DB_PATH=/path/to/libc-database/db
export LIBC_TOOL_INDEX_CACHE=/path/to/libc-database/db/.index_cache.json
export LIBC_TOOL_CORE=/path/to/libc_tool_core
export LIBC_TOOL_CACHE_DIR=/path/to/libc_tool-cache
export LIBC_TOOL_TEMPLATE_ROOT=/path/to/deploy_pwn_template
```

所有路径会在读取时转换为绝对路径。

## 匹配排序

查 ELF 时会综合多种信号排序候选 libc：

- hash / build-id / 符号地址
- 目标架构
- Ubuntu / Debian 发行版
- GLIBC 版本

默认只显示前 20 个候选。查看所有子版本或取消数量限制：

```bash
python3 libc_tool.py find --all-variants --candidate-limit 0 ./pwn
```

## 常用命令

查匹配：

```bash
python3 libc_tool.py find ./pwn
```

二级命令支持两种简写：

- 固定别名：长期稳定，推荐优先使用
- 唯一前缀：当前能唯一命中时可直接调用

固定别名：

```bash
python3 libc_tool.py f ./pwn
python3 libc_tool.py dl ./libc.so
python3 libc_tool.py pt -y ./pwn
python3 libc_tool.py rs ./pwn
python3 libc_tool.py do
python3 libc_tool.py reb
python3 libc_tool.py cc
python3 libc_tool.py ci
```

唯一前缀示例：

```bash
python3 libc_tool.py pat -y ./pwn
python3 libc_tool.py cle
python3 libc_tool.py cor
```

如果你只有一个 ELF，想自动选择推荐 libc 并继续后续下载流程，可以加 `-y`：

```bash
python3 libc_tool.py download -y ./pwn
```

在交互终端里，如果不加 `-y`，`libc_tool` 会自动启用基于 Python `prompt_toolkit` 的 TUI 选择器：

- 选择候选 `libc`
- 在 `libc` 选择界面顶部显示当前 ELF 的路径、架构、目标 GLIBC、发行版推断和候选数量，并带颜色高亮
- 选择 `docker --destroy` 要销毁的容器/镜像

如果你更喜欢旧的编号输入模式，可以临时关闭：

```bash
LIBC_TOOL_DISABLE_TUI=1 python3 libc_tool.py patch ./pwn
```

如果你只有一个 ELF，并且希望自动完成“匹配 libc -> 下载运行库 -> patch ELF”，可以直接：

```bash
python3 libc_tool.py patch -y ./pwn
```

如果你希望直接为目标 ELF 起一个容器调试环境，并把题目目录和运行库目录映射到容器里，可以直接：

```bash
python3 libc_tool.py docker -y ./pwn
```

默认行为：

- 自动匹配并准备运行库
- 根据匹配到的 `libc/ld` 推断尽量匹配的 Ubuntu 基础镜像版本
- 在目标 ELF 同目录下生成一套部署目录；模板来自 `--template` 指定的仓库模板，仓库内没有模板时才回退到 `LIBC_TOOL_TEMPLATE_ROOT`
- 生成的部署目录会自带 `bundle/challenge` 和 `bundle/runtime`，`docker-compose.yaml` 使用相对路径挂载；整个目录可直接复制到别的 Linux 上继续 `docker compose up -d --build`
- 默认把宿主机 `10001` 端口映射到容器内 `1337`
- 把部署目录里的 `./bundle/challenge` 挂载到容器内 `/challenge`
- 把部署目录里的 `./bundle/runtime` 挂载到容器内 `/runtime`
- 容器内直接执行目标 ELF，不再显式调用自定义 `ld-linux ... --library-path ...`
- `/runtime` 主要作为额外共享库来源，容器会把非 glibc 核心库整理到单独目录并通过 `LD_LIBRARY_PATH` 提供给题目

模板会影响生成的监听器和相关资产：默认 `ubuntu+socat` 使用 socat，`xinetd` 模板生成并复制 `ctf.xinetd`，`ynetd` 模板复制模板中的 `bin/ynetd`。例如：

```bash
python3 libc_tool.py docker --template ubuntu+xinetd+chroot -y --generate-only ./pwn
python3 libc_tool.py docker --template alpine+ynetd+chroot+patchelf2 -y --generate-only ./pwn
```

只生成部署文件、不立即启动容器：

```bash
python3 libc_tool.py docker -y --generate-only ./pwn
```

直接使用本地现成运行库目录：

```bash
python3 libc_tool.py docker --dir ./libc_dir ./pwn
```

如果你需要容器内额外开启 `gdbserver` 远程调试端口：

```bash
python3 libc_tool.py docker -y --gdbserver --gdb-port 1234 ./pwn
```

此时：

- 服务端口仍然走 `--port`，默认 `10001`
- `gdbserver` 会额外映射一个宿主机端口，默认 `1234`
- 部署目录里会自动生成 `debug.gdb` 和便携启动脚本 `debug.sh`
- 宿主机可直接：

```bash
./.libc_tool_docker_pwn/debug.sh
```

如果当前部署开启了 `--gdbserver`，`debug.gdb` 里会自动带上：

- 相对部署目录自动推导出的 ELF 路径
- 运行库搜索路径和 `/challenge`、`/runtime` 的路径映射
- `target remote 127.0.0.1:<gdb-port>`

注意：容器里的题目进程仍然是由服务端口触发的，所以通常要先让 `exp` 或 `nc 127.0.0.1 <port>` 连上服务端口，再执行 `./debug.sh`。

如果默认宿主机端口已经被别的题目容器占用：

- 交互终端下会自动弹出 TUI，让你选择新的服务端口或 `gdbserver` 端口
- `-y` 模式下会自动挑选附近的空闲端口继续启动
- 也仍然可以手动显式传 `--port` / `--gdb-port`

停止该 ELF 对应的容器环境：

```bash
python3 libc_tool.py docker --down ./pwn
```

如果你还希望把该 ELF 对应的 Docker 镜像也一起删除，可以使用：

```bash
python3 libc_tool.py docker ./pwn --destroy
```

这会等价执行该部署目录下的：

```bash
docker compose down --rmi all --remove-orphans
```

如果没有记住对应的 ELF 或部署目录，也可以直接：

```bash
python3 libc_tool.py docker --destroy
```

命令会列出由 `libc_tool` 创建的容器和未使用镜像，交互选择后再销毁。

仓库里也提供了一个可直接运行的本地 smoke 测试目录：

```bash
make -C tests/docker_smoke smoke
```

或：

```bash
bash tests/docker_smoke/run_smoke.sh
```

这个测试会：

- 现场编译一个最小 ELF
- 自动从宿主机提取当前 ELF 使用的 `libc.so.6` 和 `ld-linux-x86-64.so.2`
- 分别验证普通 `docker --generate-only` 和 `--gdbserver` 生成结果
- 默认把中间产物放到 `/tmp`，不污染仓库；如需保留，执行时加 `KEEP=1`

自动匹配到候选 libc 后，后续下载/patch 会优先使用索引缓存里保存的包元数据，不要求 `LIBC_DB_PATH` 下对应的原始 `.so` 仍然存在；也就是说，匹配阶段和自动下载阶段都可以主要依赖索引表完成。

直接下载某个 `libc` 的运行库：

```bash
python3 libc_tool.py download ./libc.so
```

`download` 会尽量下载并合并未 strip 的 libc：先拿 `libc6` 包，再找对应的 `libc6-dbg` / `libc6-dbgsym` 或 debuginfod 符号。若最终输出目录中没有带 `.symtab` / `.debug_info` 的 libc，会返回失败，而不是静默接受 stripped libc。

Debian/Ubuntu `Packages` 索引中的 `SHA256` 和 `Size` 会随候选 URL 保存。下载前校验包完整性，缓存目录只有在完成标记匹配时才会复用；没有索引元数据的本地 `.url` 回退源会明确提示仅进行内容哈希记录。

下载运行库并补程序依赖：

```bash
python3 libc_tool.py download --elf ./pwn ./libc.so
```

如果目标 ELF 依赖 C++ 运行库，工具会从 ELF 的 version need 中提取并校验：

- `libstdc++.so.6`: `GLIBCXX_*`、`CXXABI_*`
- `libgcc_s.so.1`: `GCC_*`

目录里已有同名库但 ABI 或运行时 libc 版本不满足时，会继续尝试其他 Debian/Ubuntu 包，避免混入宿主机过新的 `libstdc++.so.6` / `libgcc_s.so.1`。

补一个额外库：

```bash
python3 libc_tool.py download --elf ./pwn --extra-needed libstdc++.so.6 ./libc.so
```

按包名补 Debian/Ubuntu 包：

```bash
python3 libc_tool.py download --extra-package libseccomp2 ./libc.so
```

手动指定 soname 到包名映射：

```bash
python3 libc_tool.py download --elf ./pwn --package-hint libssl.so.1.1=libssl1.1 ./libc.so
```

默认输出到输入文件同目录下的 `libc_dir`，也可以自己指定：

```bash
python3 libc_tool.py download --output-dir ./my_libs --elf ./pwn ./libc.so
```

下载完成后直接 patch 目标 ELF：

```bash
python3 libc_tool.py patch ./pwn --libc ./libc.so
```

如果你本地已经有准备好的 `libc_dir`，不想再下载 libc，可以直接 patch：

```bash
python3 libc_tool.py patch --dir ./libc_dir ./pwn
```

如果你本地已经有 `libc.so.6`，并且它同目录下还有对应的 `ld-linux-x86-64.so.2` 以及目标 ELF 需要的其他运行库，也可以直接给 `--libc`，工具会优先尝试“本地直接 patch”，不够完整时才回退到下载流程：

```bash
python3 libc_tool.py patch -y --libc ./libc.so.6 ./pwn
```

默认 patch 模式是 `rpath`。如果你确实需要把主程序的 `DT_NEEDED` 绑定到 `libc_dir` 内的绝对路径，可以显式改成：

```bash
python3 libc_tool.py patch --libc ./libc.so --patch-mode replace-needed ./pwn
```

patch 时会：

- 为目标 ELF 生成 `./pwn.bak`
- 默认把运行库复制到 `./libc_dir.libc_tool_patched`，只修改隔离副本，不改动原始运行库目录
- 生成 `./pwn.libc_tool.patch.json`，记录原始/patch 后 ELF 哈希、运行库路径和受管理文件
- 默认用目标 loader 执行 `--list` 做一次依赖解析验证

只有明确指定下面的选项时才会原地修改运行库；此模式仍会创建运行库备份并由 `restore` 校验后回滚：

```bash
python3 libc_tool.py patch ./pwn --dir ./libc_dir --in-place-runtime
```

恢复原始 ELF：

```bash
python3 libc_tool.py restore ./pwn
```

重建 libc 索引缓存：

```bash
python3 libc_tool.py rebuild-index
```

清理缓存：

```bash
python3 libc_tool.py clear-cache
```

`clear-cache` 只清理工具缓存，不删除题目目录里的 `libc_dir`。清理范围包括：

- pwntools cache 下的 `libc_tool_extra_libs`
- `libcdb_libs`
- `libcdb_dbg`
- `libcdb`
- `LIBC_INDEX_CACHE`

## Debug 和运行库

debug 包里的 libc 可能是 debug-only ELF，没有 `.dynamic`，不能直接作为运行时 `libc.so.6`。工具现在会：

- 要求运行时 `libc.so.6` 必须有 `.dynamic`
- debug-only 文件另存为 `*.debug`
- 优先用 `eu-unstrip` 把 debug 符号合并到可运行 libc
- 已合并 debug 符号的 libc 不会再被源 libc 覆盖
- 即使 debug 符号获取失败，也会继续补齐 `DT_NEEDED` 依赖

本地运行旧 libc 程序时推荐用 loader 直接验证依赖解析：

```bash
./libc_dir/ld-linux-x86-64.so.2 --library-path ./libc_dir:. --list ./pwn
```

patch:

```bash
patchelf --set-interpreter "$PWD/libc_dir/ld-linux-x86-64.so.2" ./pwn
patchelf --force-rpath --set-rpath '$ORIGIN/libc_dir:$ORIGIN' ./pwn
```

如果使用 `patch`，工具会自动做上面的 interpreter/RPATH 处理；仍建议在 patch 后自己再跑一次：

```bash
./libc_dir/ld-linux-x86-64.so.2 --library-path ./libc_dir:. --list ./pwn
```
