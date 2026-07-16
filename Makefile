# ps2-tool - PS2 Reverse Engineering CLI
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -MMD -MP -Isrc

SRC := src/main.cpp src/elf_parser.cpp src/ghidra_detect.cpp src/ghidra_plugins.cpp src/export_ps2recomp.cpp
OBJ := $(SRC:.cpp=.o) src/sqlite3.o
DEP := $(OBJ:.o=.d)

TARGET := ps2-tool

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ -ldl -lpthread

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

src/sqlite3.o: src/sqlite3.c
	gcc -O2 -Wall -DSQLITE_THREADSAFE=0 -c $< -o $@

clean:
	rm -f $(OBJ) $(DEP) $(TARGET)

-include $(DEP)
.PHONY: all clean
