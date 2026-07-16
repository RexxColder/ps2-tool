#include "elf_parser.h"
#include <fstream>
#include <iostream>
#include <cstring>

// ELF constants
#define ELF_MAGIC "\x7fELF"
#define EM_MIPS 0x0008
#define ET_EXEC 2
#define PT_LOAD 1

// MIPS-specific
#define PT_MIPS_ABIFLAGS 0x60000000
#define PT_MIPS_OPTIONS  0x60000001

static uint16_t read16(const uint8_t* p, bool be) {
    return be ? (uint16_t(p[0]) << 8 | p[1]) : (uint16_t(p[1]) << 8 | p[0]);
}

static uint32_t read32(const uint8_t* p, bool be) {
    return be ? (uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3])
              : (uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0]);
}

ElfInfo parse_elf(const std::string& path) {
    ElfInfo info;
    info.filename = path;

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot open: " << path << "\n"; return info; }

    // Read ELF header (first 52 bytes for 32-bit)
    uint8_t ehdr[52];
    f.read(reinterpret_cast<char*>(ehdr), 52);
    if (f.gcount() < 52) return info;

    // Check magic
    if (memcmp(ehdr, ELF_MAGIC, 4) != 0) {
        std::cerr << "Not an ELF file: " << path << "\n";
        return info;
    }

    bool be = (ehdr[5] == 2); // big-endian
    info.machine = read16(&ehdr[18], be);
    info.type = read16(&ehdr[16], be);
    info.entry_point = read32(&ehdr[24], be);
    uint32_t phoff = read32(&ehdr[28], be);
    info.phdr_count = read16(&ehdr[44], be);
    uint32_t phentsize = read16(&ehdr[42], be);

    if (info.machine != EM_MIPS) {
        std::cerr << "Not a MIPS ELF (machine=0x" << std::hex << info.machine << ")\n";
        return info;
    }

    // Parse program headers
    info.valid = true;
    for (uint32_t i = 0; i < info.phdr_count; i++) {
        f.seekg(phoff + i * phentsize);
        uint8_t phdr[32];
        f.read(reinterpret_cast<char*>(phdr), phentsize < 32 ? phentsize : 32);

        uint32_t type = read32(&phdr[0], be);
        uint32_t offset = read32(&phdr[4], be);
        uint32_t vaddr = read32(&phdr[8], be);
        uint32_t paddr = read32(&phdr[12], be);
        uint32_t filesz = read32(&phdr[16], be);
        uint32_t memsz = read32(&phdr[20], be);

        if (type == PT_LOAD) {
            SectionInfo sec;
            sec.addr = vaddr;
            sec.offset = offset;
            sec.size = memsz;
            sec.flags = read32(&phdr[24], be);

            // Classify by address ranges (typical PS2 layout)
            if (vaddr >= 0x00100000 && vaddr < 0x01000000) {
                sec.name = ".text";
                info.text_start = vaddr;
                info.text_end = vaddr + memsz;
            } else if (vaddr >= 0x01000000 && vaddr < 0x02000000) {
                sec.name = ".data";
                info.data_start = vaddr;
                info.data_end = vaddr + memsz;
            } else if (vaddr >= 0x02000000 && vaddr < 0x03000000) {
                sec.name = ".bss";
                info.bss_start = vaddr;
                info.bss_end = vaddr + memsz;
            } else {
                sec.name = "segment_" + std::to_string(i);
            }
            info.sections.push_back(sec);
        } else if (type == PT_MIPS_ABIFLAGS) {
            // EE ABI flags section
            SectionInfo sec;
            sec.name = ".MIPS.abiflags";
            sec.addr = vaddr;
            sec.offset = offset;
            sec.size = memsz;
            info.sections.push_back(sec);
        } else if (type == PT_MIPS_OPTIONS) {
            // MIPS options
            SectionInfo sec;
            sec.name = ".MIPS.options";
            sec.addr = vaddr;
            sec.offset = offset;
            sec.size = memsz;
            info.sections.push_back(sec);
        }
    }

    // If no sections found from program headers, report basic info
    if (info.sections.empty()) {
        info.load_address = info.entry_point;
        info.text_start = info.entry_point;
        info.text_end = info.entry_point + 0x100000; // estimate
    } else {
        info.load_address = info.sections[0].addr;
    }

    return info;
}

void print_elf_info(const ElfInfo& info) {
    if (!info.valid) {
        std::cout << "Invalid ELF\n";
        return;
    }

    std::cout << "PS2 ELF Info\n"
              << "  File:           " << info.filename << "\n"
              << "  Machine:        MIPS R5900 (Emotion Engine)\n"
              << "  Type:           " << (info.type == ET_EXEC ? "Executable" : "0x" + std::to_string(info.type)) << "\n"
              << "  Entry Point:    0x" << std::hex << info.entry_point << std::dec << "\n"
              << "  Load Address:   0x" << std::hex << info.load_address << std::dec << "\n"
              << "  Segments:       " << info.phdr_count << "\n\n";

    if (info.text_start) {
        std::cout << "  .text: 0x" << std::hex << info.text_start << "-0x" << info.text_end
                  << " (" << std::dec << (info.text_end - info.text_start) << " bytes)\n";
    }
    if (info.data_start) {
        std::cout << "  .data: 0x" << std::hex << info.data_start << "-0x" << info.data_end
                  << " (" << std::dec << (info.data_end - info.data_start) << " bytes)\n";
    }
    if (info.bss_start) {
        std::cout << "  .bss:  0x" << std::hex << info.bss_start << "-0x" << info.bss_end
                  << " (" << std::dec << (info.bss_end - info.bss_start) << " bytes)\n";
    }

    if (!info.sections.empty()) {
        std::cout << "\n  All sections:\n";
        for (auto& s : info.sections) {
            std::cout << "    " << s.name << ": 0x" << std::hex << s.addr
                      << " (" << std::dec << s.size << " bytes)\n";
        }
    }
}
