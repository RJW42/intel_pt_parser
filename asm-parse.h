#ifndef ASM_PARSE_H_
#define ASM_PARSE_H_

#include "types.h"
#include "asm-types.h"


void asm_init(asm_state& state, const char* asm_file_name);
void advance_to_ipt_start(asm_state& state);

jit_asm_instruction* get_next_jit_instr(
    asm_state& state, u64 current_ip
);
u64 get_last_jmp_loc(asm_state& state);
bool ip_inside_block(asm_state& state, u64 ip);

#endif