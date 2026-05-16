# libc_tool

`libc_tool.py` 是个给 PWN / 本地调试用的脚本

- 给 ELF 找可能匹配的 `libc`
- 从已有 `libc.so` 下载整套运行库
- 按目标程序的 `DT_NEEDED` 补缺的共享库
- 按 `soname` 或 Ubuntu 包名补额外依赖
- 用 `--doctor` 先做环境检查

## 依赖

- Linux
- Python 3
- `pwntools`
- `unix_ar`
- `zstandard`（有些 `.deb` 里的 `data.tar.zst` 会用到）
- `readelf`、`objdump`、`strings`
- 能访问 `launchpad.net`、`archive.ubuntu.com`

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

下载运行库并补程序依赖：

```bash
python3 libc_tool.py --download --elf ./pwn ./libc.so
```

补一个额外库：

```bash
python3 libc_tool.py --download --elf ./pwn --extra-needed libstdc++.so.6 ./libc.so
```

按包名补：

```bash
python3 libc_tool.py --download --extra-package libseccomp2 ./libc.so
```

默认输出到输入文件同目录下的 `libc_dir`，也可以自己指定：

```bash
python3 libc_tool.py --download --output-dir ./my_libs --elf ./pwn ./libc.so
```

