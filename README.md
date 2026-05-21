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
- `unix_ar`
- `zstandard`
- `eu-unstrip`（来自 `elfutils`，用于把 `libc6-dbg` / `libc6-dbgsym` 合并成未 strip 的 libc）
- `readelf`、`objdump`、`strings`
检查：

```bash
python3 libc_tool.py --doctor
```

## libc-database

这个脚本依赖本地 `libc-database`。官方仓库：

- `https://github.com/niklasb/libc-database`


```bash
git clone https://github.com/niklasb/libc-database.git /home/starlight/CtfTools/libc-database
cd /home/starlight/CtfTools/libc-database
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
export PWN_UBUNTU_DDEBS_URL=http://ddebs.ubuntu.com
```

当前代码里硬编码全局变量：

```python
LIBC_DB_PATH = "/home/starlight/CtfTools/libc-database/db"
LIBC_INDEX_CACHE = "/home/starlight/CtfTools/libc-database/db/.index_cache.json"
```

路径需要绝对路径

## 匹配排序

查 ELF 时会综合多种信号排序候选 libc：

- hash / build-id / 符号地址
- 目标架构
- Ubuntu / Debian 发行版
- GLIBC 版本

默认只显示前 20 个候选。查看所有子版本或取消数量限制：

```bash
python3 libc_tool.py --all-variants --candidate-limit 0 ./pwn
```

## 常用命令

查匹配：

```bash
python3 libc_tool.py ./pwn
```

直接下载某个 `libc` 的运行库：

```bash
python3 libc_tool.py --download ./libc.so
```

`--download` 会尽量下载并合并未 strip 的 libc：先拿 `libc6` 包，再找对应的 `libc6-dbg` / `libc6-dbgsym` 或 debuginfod 符号。若最终输出目录中没有带 `.symtab` / `.debug_info` 的 libc，会返回失败，而不是静默接受 stripped libc。

下载运行库并补程序依赖：

```bash
python3 libc_tool.py --download --elf ./pwn ./libc.so
```

如果目标 ELF 依赖 C++ 运行库，工具会从 ELF 的 version need 中提取并校验：

- `libstdc++.so.6`: `GLIBCXX_*`、`CXXABI_*`
- `libgcc_s.so.1`: `GCC_*`


补一个额外库：

```bash
python3 libc_tool.py --download --elf ./pwn --extra-needed libstdc++.so.6 ./libc.so
```

按包名补 Debian/Ubuntu 包：

```bash
python3 libc_tool.py --download --extra-package libseccomp2 ./libc.so
```

手动指定 soname 到包名映射：

```bash
python3 libc_tool.py --download --elf ./pwn --package-hint libssl.so.1.1=libssl1.1 ./libc.so
```

默认输出到输入文件同目录下的 `libc_dir`，也可以自己指定：

```bash
python3 libc_tool.py --download --output-dir ./my_libs --elf ./pwn ./libc.so
```

重建 libc 索引缓存：

```bash
python3 libc_tool.py --rebuild-index
```

清理缓存：

```bash
python3 libc_tool.py --clear-cache
python3 libc_tool.py -C
```

`--clear-cache` / `-C` 只清理工具缓存，不删除题目目录里的 `libc_dir`。清理范围包括：

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

