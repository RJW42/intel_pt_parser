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
    bool is_breakpoint;

    jit_asm_instruction() {};
    jit_asm_instruction(jit_asm_type type, u64 loc, u64 des) :
        type(type), loc(loc), des(des), is_breakpoint(false) {};
    jit_asm_instruction(jit_asm_type type, u64 loc, bool is_breakpoint) : 
        type(type), loc(loc), is_breakpoint(is_breakpoint) {};
};

void asm_init(const char* asm_file_name);
void advance_to_mode(void);

jit_asm_instruction* get_next_jit_instr(u64 current_ip);
u64 get_last_jmp_loc(void);

bool ip_inside_block(u64 ip);

#endif