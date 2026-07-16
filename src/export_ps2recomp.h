#pragma once
#include <string>

std::string export_ps2recomp_toml(const std::string& db_path, const std::string& elf_name);
std::string export_ps2recomp_csv(const std::string& db_path, const std::string& elf_name);
