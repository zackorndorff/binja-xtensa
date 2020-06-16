#!/usr/bin/env python
"""
Script to parse ESP SDK linker script and save symbols for the ROM

File you want from the SDK is called eagle.rom.addr.v6.ld

This script will produce a known_symbols.py from it
"""

import json
import re

ROM_RE = re.compile(
    r'^\s*PROVIDE\s+\(\s*([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)\s*\);$'
)

symbols = {}

with open("eagle.rom.addr.v6.ld", "r") as f:
    for line in f:
        m = ROM_RE.match(line)
        if m:
            symbol, addr = m.groups()
            addr = int(addr, 0)
            symbols[addr] = symbol


with open("known_symbols.json", "w") as f:
    data = json.dumps(symbols)
    f.write("known_symbols = ")
    f.write(data)
    f.write("\n")
