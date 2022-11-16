#ifndef QEMU_SOURCE_PARSE_INTERNAL_H_
#define QEMU_SOURCE_PARSE_INTERNAL_H_

#include "types.h"
#include "qemu-source-parse.h"

#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <optional>


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

static src_asm_instruction parse_line(
    std::string line, std::unordered_set<std::string>& functions_to_translate,
    std::unordered_map<std::string, u64>& translated_functions
);

static src_asm_type parse_line_type(std::string line);

static void print_qemu_instruction(const src_asm_instruction& instr);


static std::optional<qemu_helper_function> get_corisponding_func(u64 loc);

static void init_loc(u64 loc);
static void init_function(std::string func_name);

// Helpers 

static bool ends_with(
    std::string const & value, std::string const & ending
);
static bool is_hex(std::string const& s);

static std::string ltrim(const std::string &s);

static std::string to_hex(u64 num);


#endif