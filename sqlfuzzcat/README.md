# Light SQLi Fuzzer v1
Lightweight SQL injection fuzzer for bug bounty hunters that likes cats ^o.o^. Inspired by sqlmap and ffuf. Optimized for low-spec hardware

## Features
- Minimal deps: `requests` ,`aiohttp` for async.
- Secure: Input validation, no eval/exec.

## Installation
```bash
pip install requests
pip install aiohttp
```

## Usage
```bash
python sql_fuzzcat.py -u "http://127.0.0.1:8000/search?q={query}" -p query [--sync]
```




