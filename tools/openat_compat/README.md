# openat Compatibility Test Generator

Tests Linux `open`/`openat` syscall compatibility by running test cases
on Linux and recording errno results to CSV for comparison with Asterinas.

## Coverage

17 O_* flags, 24 constraint rules, ~900k valid test cases.

## Build
```bash
make
```

## Usage
```bash
# Quick test (~2 minutes)
sudo ./ultimate_test_gen --base /tmp/test --out linux.csv --max 10000

# Full test (~3-4 hours)
sudo ./ultimate_test_gen --base /tmp/test --out linux.csv --progress 10000
```

## Requirements

- Linux x86-64
- gcc
- Root privileges
```
