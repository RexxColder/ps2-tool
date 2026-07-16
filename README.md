# ps2-tool

Native C++ CLI for PlayStation 2 reverse engineering. No Wine, no Python runtime.

## Features

- **ELF Parser** — PS2 ELF metadata (entry point, sections, load address)
- **Ghidra Integration** — Auto-detect Ghidra, install Emotion Engine plugin
- **PS2 Analysis** — Ghidra headless with Emotion Engine processor
- **SDK Matching** — SHA-1 + instruction pattern matching against SCE database
- **PS2Recomp Export** — Generate CSV function map + TOML config

## Build

```bash
make
```

Requires: g++ (C++17), gcc, Java 17+ (for Ghidra runtime)

## Usage

```bash
# Show ELF info
./ps2-tool info game.elf

# Setup Ghidra + install EE plugin
./ps2-tool ghidra-setup

# Match SDK functions (needs ELF + analysis DB)
./ps2-tool match-sce game.elf sce_flat.txt analysis.db

# Full analysis (needs Ghidra installed)
./ps2-tool analyze game.elf output/

# Export PS2Recomp
./ps2-tool export --db analysis.db --elf game.elf
```

## SDK Matching

The `match-sce` command identifies SDK functions by:
1. SHA-1 exact matching against 9,218 known signatures
2. Instruction pattern + size fallback matching

For best results, run Ghidra analysis first (`analyze` command) which uses built-in signature matching.

## Plugins

- **Emotion Engine Reloaded** — PS2 EE + VU0 + COP0/1/2 processor/decompiler
  - Source: [ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded)
  - Bundled in `plugins/` for auto-install

## Dependencies

- **Build**: g++ (C++17), gcc
- **Runtime**: Java 17+ (Ghidra)
- **Built-in**: SQLite (amalgamation), ELF parser, SHA-1
