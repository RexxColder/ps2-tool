# ps2-tool

Native C++ CLI for PlayStation 2 reverse engineering. No Wine, no Python runtime.

## Features

- **ELF Parser** — PS2 ELF metadata (entry point, sections, load address)
- **Ghidra Integration** — Auto-detect Ghidra, install Emotion Engine plugin
- **PS2 Analysis** — Ghidra headless with Emotion Engine processor
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

# Full analysis
./ps2-tool analyze game.elf output/

# Export PS2Recomp
./ps2-tool export --db output/game.db --elf game.elf
```

## Plugins

- **Emotion Engine Reloaded** — PS2 EE + VU0 + COP0/1/2 processor/decompiler
  - Source: [ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded)
  - Bundled in `plugins/` for auto-install

## Dependencies

- **Build**: g++ (C++17), gcc
- **Runtime**: Java 17+ (Ghidra)
- **Built-in**: SQLite (amalgamation), ELF parser
