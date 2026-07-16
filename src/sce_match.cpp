#include "sce_match.h"
#include "sha1.h"
#include "sqlite3.h"
#include <fstream>
#include <iostream>

std::map<std::string, SceDbEntry> load_sce_database(const std::string& path) {
    std::map<std::string, SceDbEntry> db;
    std::ifstream f(path);
    if (!f) { std::cerr << "Cannot open: " << path << "\n"; return db; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        size_t p1 = line.find('|'), p2 = line.find('|', p1+1), p3 = line.find('|', p2+1);
        if (p1==std::string::npos || p2==std::string::npos || p3==std::string::npos) continue;
        std::string sha1 = line.substr(0, p1);
        int size = std::stoi(line.substr(p3+1));
        if (sha1.size() == 40) db[sha1] = {line.substr(p1+1, p2-p1-1), line.substr(p2+1, p3-p2-1), size};
    }
    std::cout << "  " << db.size() << " SCE signatures loaded\n";
    return db;
}

// Match by SHA-1, then by instruction pattern (first 4 bytes) + size
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

    // Build size -> [(sha1, entry)] index for fast lookup
    std::map<int, std::vector<std::pair<std::string, SceDbEntry*>>> by_size;
    for (auto& [sha, entry] : sce_db)
        by_size[entry.size].push_back({sha, (SceDbEntry*)&entry});

    for (auto& [addr, b] : functions) {
        uint64_t sz = b.second - b.first;
        if (sz < 4 || sz > 2048 || b.first + sz > fsz) continue;

        // Try SHA-1 match first
        std::string h = SHA1::hash_hex(elf.data() + b.first, sz);
        auto it = sce_db.find(h);
        if (it != sce_db.end()) {
            matches[addr] = {it->second.library, it->second.name, it->second.size};
            continue;
        }

        // Fallback: match by first 4 bytes (instruction pattern) + size
        if (sz >= 8) {
            uint32_t first_word = (uint32_t(elf[b.first]) << 24) | (uint32_t(elf[b.first+1]) << 16) |
                                  (uint32_t(elf[b.first+2]) << 8) | elf[b.first+3];
            // Check common SDK prologues
            // lui r28, 0x10; jr r31; nop  (common in SCE stubs)
            // lw r4, 0(r3); jr r31; nop   (simple return)
            // addiu r1, r1, X; jr r31; ld r31, X-8(r1) (function epilogue)
            if ((first_word & 0xFFFF0000) == 0x3C1C0000 || // lui r28, imm
                (first_word & 0xFC000000) == 0x8C000000 || // lw rX, offset(rY)
                (first_word & 0xFFFF0000) == 0x27BD0000) { // addiu r1, r1, imm
                // Match by size
                auto size_it = by_size.find((int)sz);
                if (size_it != by_size.end()) {
                    for (auto& [sha, entry] : size_it->second) {
                        if (entry->size == (int)sz) {
                            matches[addr] = {entry->library, entry->name, entry->size};
                            break;
                        }
                    }
                }
            }
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
    if (sqlite3_prepare_v2(db, "UPDATE functions SET name=? WHERE address=? AND (name LIKE 'sub_%' OR name LIKE 'nullsub_%')", -1, &s, nullptr) == SQLITE_OK) {
        for (auto& [a, m] : matches) { sqlite3_bind_text(s, 1, m.name.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(s, 2, a); sqlite3_step(s); sqlite3_reset(s); }
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
}
