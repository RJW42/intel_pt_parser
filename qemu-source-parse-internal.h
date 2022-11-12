#ifndef QEMU_SOURCE_PARSE_INTERNAL_H_
#define QEMU_SOURCE_PARSE_INTERNAL_H_

#include "types.h"

#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <optional>

enum qemu_asm_type {
    JMP,
    JXX,
    CALL,
    RET,
    OTHER
};


struct qemu_asm_instruction {
    qemu_asm_type type;
    u64 loc;
    std::optional<u64> des;

    qemu_asm_instruction() {};
    qemu_asm_instruction(qemu_asm_type type, u64 loc) :
        type(type), loc(loc) {};
    qemu_asm_instruction(qemu_asm_type type, u64 loc, std::optional<u64> des) :
        type(type), loc(loc), des(des) {};
};


struct qemu_helper_function {
    u64 start;
    u64 size;
    std::string *name;
};


static void search_for_helper_calls(
    const char* translated_source_file_name, 
    std::unordered_set<std::string>& helpers_to_translate
);

static void parse_helper_calls(
    const char* qemu_source_file_name,
    std::unordered_set<std::string>& functions_to_translate,
    std::unordered_map<std::string, u64>& translated_functions
);

static void find_and_parse_jump_region(
    const char* qemu_source_file_name, u64 jump_loc, 
    std::unordered_map<std::string, u64>& translated_functions
);

static qemu_asm_instruction parse_line(
    std::string line, std::unordered_set<std::string>& functions_to_translate,
    std::unordered_map<std::string, u64>& translated_functions
);

static qemu_asm_type parse_line_type(std::string line);


static std::optional<qemu_helper_function> get_corisponding_func(u64 loc);


// Helpers 

static bool ends_with(
    std::string const & value, std::string const & ending
);
static bool is_hex(std::string const& s);

static std::string ltrim(const std::string &s);

static std::string to_hex(u64 num);


#endif