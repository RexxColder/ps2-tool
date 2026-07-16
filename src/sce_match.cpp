#include "sce_match.h"
#include "sha1.h"
#include "sqlite3.h"
#include <fstream>
#include <iostream>
#include <sstream>

// Load SDK function names from Ghidra output (functions.csv)
// or from reference config.toml format
std::map<std::string, SceDbEntry> load_sce_database(const std::string& path) {
    std::map<std::string, SceDbEntry> db;
    std::ifstream f(path);
    if (!f) { std::cerr << "Cannot open: " << path << "\n"; return db; }

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // Format: sha1|library|function_name|size
        size_t p1 = line.find('|'), p2 = line.find('|', p1+1), p3 = line.find('|', p2+1);
        if (p1==std::string::npos || p2==std::string::npos || p3==std::string::npos) continue;
        std::string sha1 = line.substr(0, p1);
        int size = std::stoi(line.substr(p3+1));
        if (sha1.size() == 40) db[sha1] = {line.substr(p1+1, p2-p1-1), line.substr(p2+1, p3-p2-1), size};
    }
    std::cout << "  " << db.size() << " SCE signatures loaded\n";
    return db;
}

// Load SDK addresses from config.toml format: "FuncName@0xADDR",
std::map<uint64_t, std::string> load_sdk_addresses(const std::string& config_path) {
    std::map<uint64_t, std::string> addrs;
    std::ifstream f(config_path);
    if (!f) return addrs;
    std::string line;
    while (std::getline(f, line)) {
        // Look for lines like: "AddDmacHandler@0x00114070",
        size_t q1 = line.find('"');
        size_t q2 = line.find('"', q1 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos) continue;
        std::string entry = line.substr(q1 + 1, q2 - q1 - 1);
        size_t at = entry.find('@');
        if (at == std::string::npos) continue;
        std::string name = entry.substr(0, at);
        std::string addr_str = entry.substr(at + 1);
        if (addr_str.size() > 2 && addr_str[0] == '0' && addr_str[1] == 'x') {
            try {
                uint64_t addr = std::stoull(addr_str.substr(2), nullptr, 16);
                addrs[addr] = name;
            } catch (...) { continue; }
        }
    }
    return addrs;
}

// Match functions: SHA-1 exact + name pattern + SDK address lookup
std::map<uint64_t, SceMatch> match_sce_functions(
    const std::string& elf_path,
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>>& functions,
    const std::map<std::string, SceDbEntry>& sce_db) {

    std::map<uint64_t, SceMatch> matches;
    std::ifstream f(elf_path, std::ios::binary | std::ios::ate);
    if (!f) return matches;
    size_t fsz = f.tellg(); f.seekg(0);
    std::vector<uint8_t> elf(fsz);
    f.read(reinterpret_cast<char*>(elf.data()), fsz);

    for (auto& [addr, b] : functions) {
        uint64_t sz = b.second - b.first;
        if (sz < 4 || sz > 2048 || b.first + sz > fsz) continue;

        // Try SHA-1 exact match
        std::string h = SHA1::hash_hex(elf.data() + b.first, sz);
        auto it = sce_db.find(h);
        if (it != sce_db.end()) {
            matches[addr] = {it->second.library, it->second.name, it->second.size};
            continue;
        }

        // Pattern: first instruction is jr r31 (function return stub)
        uint32_t first_word = (uint32_t(elf[b.first]) << 24) | (uint32_t(elf[b.first+1]) << 16) |
                              (uint32_t(elf[b.first+2]) << 8) | elf[b.first+3];
        bool is_stub = ((first_word & 0xFC1FFFFF) == 0x03E00008) || // jr r31
                       ((first_word >> 26) == 0x02); // j target

        if (is_stub && sz <= 32) {
            // This looks like a stub - check if any SCE function has matching size
            for (auto& [sha, entry] : sce_db) {
                if (entry.size == (int)sz) {
                    matches[addr] = {entry.library, entry.name, entry.size};
                    break;
                }
            }
        }
    }
    return matches;
}

// Match using SDK address list from config.toml
std::map<uint64_t, SceMatch> match_sdk_addresses(
    const std::map<uint64_t, std::string>& sdk_addrs,
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>>& functions) {

    std::map<uint64_t, SceMatch> matches;
    for (auto& [addr, name] : sdk_addrs) {
        if (functions.count(addr)) {
            auto& [start, end] = functions.at(addr);
            // Determine library from name prefix
            std::string lib = "unknown";
            if (name.find("sce") == 0 || name.find("Sif") == 0 || name.find("Gs") == 0) lib = "libps2sdk";
            else if (name.find("Pad") == 0) lib = "libpad";
            else if (name.find("Mc") == 0) lib = "libmc";
            else if (name.find("Cd") == 0 || name.find("sceCd") == 0) lib = "libcdvd";
            else if (name.find("Dma") == 0) lib = "libdma";
            else if (name.find("Vif") == 0) lib = "libvif";
            else if (name.find("Gif") == 0) lib = "libgif";
            else if (name.find("Mpeg") == 0) lib = "libmpeg";
            else if (name.find("Spu") == 0) lib = "libspu";
            else if (name.find("Iop") == 0) lib = "libiop";
            else if (name.find("Vpu") == 0) lib = "libvpu";

            matches[addr] = {lib, name, (int)(end - start)};
        }
    }
    return matches;
}

void update_db_sdk_categories(const std::string& db_path, const std::map<uint64_t, SceMatch>& matches) {
    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) return;
    sqlite3_exec(db, "ALTER TABLE functions ADD COLUMN library TEXT DEFAULT ''", nullptr, nullptr, nullptr);
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "UPDATE functions SET category='sdk',library=? WHERE address=?", -1, &s, nullptr) == SQLITE_OK) {
        for (auto& [a, m] : matches) { sqlite3_bind_text(s, 1, m.library.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(s, 2, a); sqlite3_step(s); sqlite3_reset(s); }
        sqlite3_finalize(s);
    }
    if (sqlite3_prepare_v2(db, "UPDATE functions SET name=? WHERE address=? AND (name LIKE 'sub_%' OR name LIKE 'nullsub_%' OR name LIKE 'FUN_%')", -1, &s, nullptr) == SQLITE_OK) {
        for (auto& [a, m] : matches) { sqlite3_bind_text(s, 1, m.name.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(s, 2, a); sqlite3_step(s); sqlite3_reset(s); }
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
}

// Export updated CSV with SDK categories
void export_sdk_csv(const std::string& csv_path, const std::map<uint64_t, SceMatch>& matches) {
    // Read original CSV
    std::ifstream in(csv_path);
    if (!in) return;
    std::string header;
    std::getline(in, header);

    std::string out_path = csv_path + ".sdk";
    std::ofstream out(out_path);
    out << header << ",sdk_library,sdk_function\n";

    std::string line;
    while (std::getline(in, line)) {
        size_t comma = line.find(',');
        if (comma == std::string::npos) { out << line << ",,\n"; continue; }
        uint64_t addr = std::stoull(line.substr(0, comma), nullptr, 16);
        auto it = matches.find(addr);
        if (it != matches.end()) {
            out << line << "," << it->second.library << "," << it->second.name << "\n";
        } else {
            out << line << ",,\n";
        }
    }
    out.close();
    std::cout << "  SDK CSV: " << out_path << "\n";
}
