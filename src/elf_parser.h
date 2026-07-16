#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct SectionInfo {
    std::string name;
    uint32_t addr;
    uint32_t offset;
    uint32_t size;
    uint32_t flags;
};

struct ElfInfo {
    bool valid = false;
    std::string filename;
    uint32_t entry_point = 0;
    uint32_t load_address = 0;
    uint32_t text_start = 0, text_end = 0;
    uint32_t data_start = 0, data_end = 0;
    uint32_t bss_start = 0, bss_end = 0;
    uint32_t machine = 0;
    uint32_t type = 0;
    uint32_t phdr_count = 0;
    std::vector<SectionInfo> sections;
};

ElfInfo parse_elf(const std::string& path);
void print_elf_info(const ElfInfo& info);
