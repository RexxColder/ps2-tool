#include <unistd.h>
#include "sqlite3.h"
// ps2-tool - PS2 Reverse Engineering CLI
#include "elf_parser.h"
#include "ghidra_detect.h"
#include "ghidra_plugins.h"
#include "export_ps2recomp.h"
#include "sce_match.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

static void usage() {
    std::cout << "ps2-tool - PS2 Reverse Engineering CLI\n\n"
              << "Commands:\n"
              << "  info          <game.elf>                 Show ELF metadata\n"
              << "  analyze       <game.elf> <out>            Ghidra headless analysis\n"
              << "  match-sce     <game.elf> <db> <out_db>    Match SDK functions via SHA-1\n"
              << "  export        --db <db> --elf <name>      PS2Recomp TOML/CSV\n"
              << "  ghidra-setup                              Detect Ghidra + install EE plugin\n";
}

static std::string get_script_dir() {
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return ".";
    exe_path[len] = '\0';
    return fs::path(exe_path).parent_path().string();
}

static int cmd_info(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: ps2-tool info <game.elf>\n"; return 1; }
    auto info = parse_elf(argv[2]);
    print_elf_info(info);
    return info.valid ? 0 : 1;
}

static int cmd_ghidra_setup(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "Detecting Ghidra...\n";
    auto ghidra = find_ghidra();
    if (!ghidra.found) {
        std::cout << "\nGhidra NOT FOUND\n";
        std::cout << "Searched: $GHIDRA_HOME, /opt/*, ~/ghidra*, /mnt/Datos/Herramientas/*\n\n";
        std::cout << "Enter Ghidra path (or press Enter to skip): ";
        std::string user_path;
        std::getline(std::cin, user_path);

        // Trim whitespace
        while (!user_path.empty() && (user_path.back() == '\n' || user_path.back() == '\r'))
            user_path.pop_back();

        if (user_path.empty()) {
            std::cout << "Install from: https://ghidra-sre.org/\n";
            std::cout << "Then: export GHIDRA_HOME=/path/to/ghidra\n";
            return 1;
        }

        // Validate the path
        if (!fs::is_directory(user_path)) {
            std::cerr << "ERROR: Directory not found: " << user_path << "\n";
            return 1;
        }

        std::string headless = "";
        // Check if user_path itself contains analyzeHeadless
        auto hl = fs::path(user_path) / "support" / "analyzeHeadless";
        if (fs::exists(hl)) {
            headless = hl.string();
        } else {
            // Search for ghidra_* subdirectories inside user_path
            for (auto& p : fs::directory_iterator(user_path)) {
                std::string name = p.path().filename().string();
                if (name.find("ghidra") != std::string::npos && p.is_directory()) {
                    auto sub_hl = p.path() / "support" / "analyzeHeadless";
                    if (fs::exists(sub_hl)) {
                        headless = sub_hl.string();
                        // Update path to the ghidra_* subdir
                        user_path = p.path().string();
                        break;
                    }
                }
            }
        }

        if (headless.empty()) {
            std::cerr << "ERROR: analyzeHeadless not found in " << user_path << "\n";
            std::cerr << "Make sure this is a valid Ghidra installation.\n";
            return 1;
        }

        // Manually populate GhidraInfo
        ghidra.found = true;
        ghidra.path = user_path;
        ghidra.analyze_headless = headless;
        // Extract version
        for (auto& p : fs::directory_iterator(user_path)) {
            std::string name = p.path().filename().string();
            if (name.find("ghidra_") == 0 && p.is_directory()) {
                auto ver = p.path().filename().string();
                auto pos = ver.find("ghidra_");
                if (pos != std::string::npos) {
                    std::string v = ver.substr(pos + 7);
                    auto end = v.find("_PUBLIC");
                    if (end != std::string::npos) v = v.substr(0, end);
                    ghidra.version = v;
                }
                break;
            }
        }
        if (ghidra.version.empty()) ghidra.version = "unknown";

        // Check Java
        ghidra.has_java = !exec_cmd("which java 2>/dev/null").empty();

        std::cout << "\nUsing Ghidra " << ghidra.version << " at " << ghidra.path << "\n";
    } else {
        std::cout << "Found Ghidra " << ghidra.version << " at " << ghidra.path << "\n";
    }

    std::cout << "Java: " << (ghidra.has_java ? "OK" : "NOT FOUND") << "\n";
    if (!ghidra.has_java) { std::cerr << "ERROR: Java not found\n"; return 1; }
    std::cout << "\nChecking plugins...\n";
    check_and_install_all(ghidra);
    std::cout << "\nSetup complete.\n";
    return 0;
}

static int cmd_analyze(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: ps2-tool analyze <game.elf> <out>\n"; return 1; }
    auto ghidra = find_ghidra();
    if (!ghidra.found) { std::cerr << "Ghidra not found. Run: ps2-tool ghidra-setup\n"; return 1; }
    std::string input = argv[2], output = argv[3];
    fs::create_directories(output);
    std::string proj = output + "/ghidra_project";
    fs::create_directories(proj);
    std::string cmd = ghidra.analyze_headless + " \"" + proj + "\" ps2_analysis"
        + " -import \"" + input + "\""
        + " -analysisTimeoutPerFile 600 -deleteProject 2>&1";
    std::cout << "PS2 Ghidra Analysis: " << input << " -> " << output << "\n";
    return system(cmd.c_str());
}

static int cmd_match_sce(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "Usage: ps2-tool match-sce <game.elf> <sce_db.json> <analysis.db>\n";
        std::cerr << "  Reads ELF + analysis DB, matches functions against SCE database,\n";
        std::cerr << "  updates DB with SDK categories and library names.\n";
        return 1;
    }
    std::string elf_path = argv[2];
    std::string sce_db_path = argv[3];
    std::string analysis_db = argv[4];

    std::cout << "Loading SCE database: " << sce_db_path << "\n";
    auto sce_db = load_sce_database(sce_db_path);
    std::cout << "  " << sce_db.size() << " SHA-1 signatures loaded\n";

    // Read functions from analysis DB
    std::map<uint64_t, std::pair<uint64_t, uint64_t>> functions;
    {
        sqlite3* db = nullptr;
        if (sqlite3_open(analysis_db.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Cannot open DB: " << analysis_db << "\n";
            return 1;
        }
        sqlite3_stmt* stmt = nullptr;
        std::string q = "SELECT address, size FROM functions ORDER BY address";
        if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                uint64_t addr = sqlite3_column_int64(stmt, 0);
                uint64_t size = sqlite3_column_int64(stmt, 1);
                functions[addr] = {addr, addr + size};
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    std::cout << "  " << functions.size() << " functions to match\n";

    // Match
    std::cout << "Matching against ELF: " << elf_path << "\n";
    auto matches = match_sce_functions(elf_path, functions, sce_db);
    std::cout << "  " << matches.size() << " matches found\n";

    // Show some matches
    int shown = 0;
    for (auto& [addr, m] : matches) {
        if (shown++ >= 10) break;
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%08X", (uint32_t)addr);
        std::cout << "  " << hex << " -> " << m.library << "." << m.name << "\n";
    }
    if (matches.size() > 10)
        std::cout << "  ... and " << (matches.size() - 10) << " more\n";

    // Update DB
    std::cout << "Updating database...\n";
    update_db_sdk_categories(analysis_db, matches);
    std::cout << "Done.\n";

    return 0;
}

static int cmd_export(int argc, char** argv) {
    std::string db, elf;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--db" && i+1 < argc) db = argv[++i];
        else if (a == "--elf-name" && i+1 < argc) elf = argv[++i];
    }
    if (db.empty() || elf.empty()) {
        std::cerr << "Usage: ps2-tool export --db <db> --elf-name <name>\n";
        return 1;
    }
    std::string toml = export_ps2recomp_toml(db, elf);
    std::string csv = export_ps2recomp_csv(db, elf);
    std::ofstream tf("ps2recomp_config.toml"); tf << toml;
    std::ofstream cf("functions.csv"); cf << csv;
    std::cout << "TOML: ps2recomp_config.toml\nCSV:  functions.csv\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "info")          return cmd_info(argc, argv);
    if (cmd == "ghidra-setup")  return cmd_ghidra_setup(argc, argv);
    if (cmd == "analyze")       return cmd_analyze(argc, argv);
    if (cmd == "match-sce")     return cmd_match_sce(argc, argv);
    if (cmd == "export")        return cmd_export(argc, argv);
    usage(); return 1;
}
