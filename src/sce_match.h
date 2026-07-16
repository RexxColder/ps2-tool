#pragma once
#include <string>
#include <map>
#include <vector>
#include <cstdint>

struct SceMatch {
    std::string library;
    std::string name;
    int size;
};

struct SceDbEntry {
    std::string library;
    std::string name;
    int size;
};

// Load SCE database from JSON file
// Returns: sha1_hash -> SceDbEntry
std::map<std::string, SceDbEntry> load_sce_database(const std::string& json_path);

// Match functions in ELF against SCE database
// Returns: address -> SceMatch
std::map<uint64_t, SceMatch> match_sce_functions(
    const std::string& elf_path,
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>>& functions, // addr -> (start, end)
    const std::map<std::string, SceDbEntry>& sce_db
);

// Update SQLite DB with SDK categories
void update_db_sdk_categories(
    const std::string& db_path,
    const std::map<uint64_t, SceMatch>& matches
);
