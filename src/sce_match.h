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

std::map<std::string, SceDbEntry> load_sce_database(const std::string& path);
std::map<uint64_t, std::string> load_sdk_addresses(const std::string& config_path);

std::map<uint64_t, SceMatch> match_sce_functions(
    const std::string& elf_path,
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>>& functions,
    const std::map<std::string, SceDbEntry>& sce_db);

std::map<uint64_t, SceMatch> match_sdk_addresses(
    const std::map<uint64_t, std::string>& sdk_addrs,
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>>& functions);

void update_db_sdk_categories(const std::string& db_path, const std::map<uint64_t, SceMatch>& matches);
void export_sdk_csv(const std::string& csv_path, const std::map<uint64_t, SceMatch>& matches);
