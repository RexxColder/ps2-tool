// ps2-tool - PS2 Reverse Engineering CLI
#include "elf_parser.h"
#include "ghidra_detect.h"
#include "ghidra_plugins.h"
#include "export_ps2recomp.h"
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
              << "  export        --db <db> --elf <name>      PS2Recomp TOML/CSV\n"
              << "  ghidra-setup                              Detect Ghidra + install EE plugin\n";
}

static std::string getArg(int argc, char** argv, int idx, const std::string& def = "") {
    return (idx < argc) ? argv[idx] : def;
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
        std::cout << "\nGhidra NOT FOUND\n\n";
        std::cout << "Install from: https://ghidra-sre.org/\n";
        std::cout << "Then: export GHIDRA_HOME=/path/to/ghidra\n";
        return 1;
    }
    std::cout << "Found Ghidra " << ghidra.version << " at " << ghidra.path << "\n";
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

    // Emotion Engine processor for PS2
    std::string spec = "EmotionEngine:LE:32:default";

    std::string cmd = ghidra.analyze_headless + " \"" + proj + "\" ps2_analysis"
        + " -import \"" + input + "\""
        + " -processor " + spec
        + " -analysisTimeoutPerFile 600"
        + " -deleteProject"
        + " 2>&1";

    std::cout << "PS2 Ghidra Analysis\n"
              << "  Processor: " << spec << "\n"
              << "  Input: " << input << "\n"
              << "  Output: " << output << "\n\n";

    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "Analysis failed (exit " << ret << ")\n";
        return ret;
    }

    std::cout << "\nAnalysis complete: " << output << "\n";
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
    std::ofstream tf("ps2recomp_config.toml"); tf << export_ps2recomp_toml(db, elf);
    std::ofstream cf("functions.csv"); cf << export_ps2recomp_csv(db, elf);
    std::cout << "TOML: ps2recomp_config.toml\nCSV:  functions.csv\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "info")          return cmd_info(argc, argv);
    if (cmd == "ghidra-setup")  return cmd_ghidra_setup(argc, argv);
    if (cmd == "analyze")       return cmd_analyze(argc, argv);
    if (cmd == "export")        return cmd_export(argc, argv);
    usage(); return 1;
}
