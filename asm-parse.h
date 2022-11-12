#ifndef ASM_PARSE_H_
#define ASM_PARSE_H_

#include "types.h"


enum jit_asm_type {
    JIT_JXX,
    JIT_JMP,
    JIT_CALL
};

struct jit_asm_instruction {
    jit_asm_type type;
    u64 loc;
    u64 des;

    jit_asm_instruction() {};
    jit_asm_instruction(jit_asm_type type, u64 loc, u64 des) :
        type(type), loc(loc), des(des) {};
};

void asm_init(const char* asm_file_name);
void advance_to_mode(void);

jit_asm_instruction get_next_jit_instr(u64 current_ip);

bool ip_inside_block(u64 ip);

#endif