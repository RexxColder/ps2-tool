#pragma once
#include <string>

struct GhidraInfo {
    bool found = false;
    std::string path;
    std::string version;
    std::string analyze_headless;
    bool has_java = false;
};

GhidraInfo find_ghidra();
