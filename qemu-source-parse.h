#ifndef QEMU_SOURCE_PARSE_H_
#define QEMU_SOURCE_PARSE_H_

#include "types.h"

#include <string>
#include <optional>

enum src_asm_type {
    SRC_JMP,
    SRC_JXX,
    SRC_CALL,
    SRC_RET,
    SRC_OTHER
};


struct src_asm_instruction {
    src_asm_type type;
    u64 loc;
    std::optional<u64> des;

    src_asm_instruction() {};
    src_asm_instruction(src_asm_type type, u64 loc) :
        type(type), loc(loc) {};
    src_asm_instruction(src_asm_type type, u64 loc, std::optional<u64> des) :
        type(type), loc(loc), des(des) {};
};

void qemu_source_init(const char* qemu_source_file_name, const char* translated_source_file_name);

u64 get_call_loc(std::string func_name);
std::string get_call_name(u64 loc);

src_asm_instruction get_next_src_instr(u64 current_ip);
bool ip_inside_func(u64 ip);

#endif