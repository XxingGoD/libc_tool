# docker_smoke

This directory provides a local smoke test for the `libc_tool.py docker`
subcommand.

## What it checks

- builds a minimal dynamically linked ELF
- extracts the host loader and `libc.so.6` used by that ELF
- runs `docker --generate-only`
- runs `docker --generate-only --gdbserver`
- verifies that the generated bundle contains the expected files and settings

## Run

```bash
make -C tests/docker_smoke smoke
```

or:

```bash
bash tests/docker_smoke/run_smoke.sh
```

By default the script creates its working directory under `/tmp` and removes it
after success. Use `KEEP=1` to keep the generated directories for inspection:

```bash
KEEP=1 bash tests/docker_smoke/run_smoke.sh
```
