#include "elf_parser.h"
#include <fstream>
#include <iostream>
#include <cstring>

static const char ELF_MAGIC[] = {0x7f, 0x45, 0x4c, 0x46};
#define EM_MIPS 0x0008
#define ET_EXEC 2
#define PT_LOAD 1

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

    uint8_t ehdr[52];
    f.read(reinterpret_cast<char*>(ehdr), 52);
    if (f.gcount() < 52) return info;

    if (memcmp(ehdr, ELF_MAGIC, 4) != 0) {
        std::cerr << "Not an ELF file: " << path << "\n";
        return info;
    }

    bool be = (ehdr[5] == 2);
    info.machine = read16(&ehdr[18], be);
    info.type = read16(&ehdr[16], be);
    info.entry_point = read32(&ehdr[24], be);
    uint32_t phoff = read32(&ehdr[28], be);
    info.phdr_count = read16(&ehdr[44], be);
    uint32_t phentsize = read16(&ehdr[42], be);

    if (info.machine != EM_MIPS) {
        std::cerr << "Not MIPS (machine=0x" << std::hex << info.machine << ")\n";
        return info;
    }

    info.valid = true;
    int text_count = 0, data_count = 0;

    for (uint32_t i = 0; i < info.phdr_count; i++) {
        f.seekg(phoff + i * phentsize);
        uint8_t phdr[32];
        f.read(reinterpret_cast<char*>(phdr), phentsize < 32 ? phentsize : 32);

        uint32_t type = read32(&phdr[0], be);
        uint32_t offset = read32(&phdr[4], be);
        uint32_t vaddr = read32(&phdr[8], be);
        uint32_t memsz = read32(&phdr[20], be);
        uint32_t flags = read32(&phdr[24], be);

        if (type == PT_LOAD) {
            SectionInfo sec;
            sec.addr = vaddr;
            sec.offset = offset;
            sec.size = memsz;
            sec.flags = flags;

            // Classify by flags: PF_X=1, PF_W=2, PF_R=4
            if (flags & 1) { // executable
                sec.name = ".text" + (text_count > 0 ? std::to_string(text_count) : "");
                text_count++;
                if (!info.text_start || vaddr < info.text_start) info.text_start = vaddr;
                if (vaddr + memsz > info.text_end) info.text_end = vaddr + memsz;
            } else if (flags & 2) { // writable
                sec.name = ".data" + (data_count > 0 ? std::to_string(data_count) : "");
                data_count++;
                if (!info.data_start) info.data_start = vaddr;
                info.data_end = vaddr + memsz;
            } else { // read-only
                sec.name = ".rdata";
            }
            info.sections.push_back(sec);
        }
    }

    if (info.sections.empty()) {
        info.load_address = info.entry_point;
        info.text_start = info.entry_point;
        info.text_end = info.entry_point + 0x100000;
    } else {
        info.load_address = info.sections[0].addr;
    }

    return info;
}

void print_elf_info(const ElfInfo& info) {
    if (!info.valid) { std::cout << "Invalid ELF\n"; return; }

    std::cout << "PS2 ELF Info\n"
              << "  File:           " << info.filename << "\n"
              << "  Machine:        MIPS R5900 (Emotion Engine)\n"
              << "  Type:           " << (info.type == ET_EXEC ? "Executable" : "0x" + std::to_string(info.type)) << "\n"
              << "  Entry Point:    0x" << std::hex << info.entry_point << std::dec << "\n"
              << "  Load Address:   0x" << std::hex << info.load_address << std::dec << "\n"
              << "  Segments:       " << info.phdr_count << "\n\n";

    std::cout << "  Sections:\n";
    for (auto& s : info.sections) {
        std::string flags_str;
        if (s.flags & 1) flags_str += "X";
        if (s.flags & 2) flags_str += "W";
        if (s.flags & 4) flags_str += "R";
        std::cout << "    " << s.name << ": 0x" << std::hex << s.addr
                  << " (" << std::dec << s.size << " bytes, " << flags_str << ")\n";
    }
}
