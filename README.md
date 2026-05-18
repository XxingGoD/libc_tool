# libc_tool

`libc_tool.py` 是个给 PWN / 本地调试用的脚本

- 给 ELF 找可能匹配的 `libc`
- 从已有 `libc.so` 下载整套运行库
- 按目标程序的 `DT_NEEDED` 补缺的共享库
- 按 `soname` 或 Debian/Ubuntu 包名补额外依赖
- 用 `--doctor` 先做环境检查

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

补一个额外库：

```bash
python3 libc_tool.py --download --elf ./pwn --extra-needed libstdc++.so.6 ./libc.so
```

按包名补 Debian/Ubuntu 包：

```bash
python3 libc_tool.py --download --extra-package libseccomp2 ./libc.so
```

默认输出到输入文件同目录下的 `libc_dir`，也可以自己指定：

```bash
python3 libc_tool.py --download --output-dir ./my_libs --elf ./pwn ./libc.so
```
