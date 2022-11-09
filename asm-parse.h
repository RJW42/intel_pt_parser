#ifndef ASM_PARSE_H_
#define ASM_PARSE_H_

#include "types.h"

struct jmp {
    // Todo: need to add conditoinal or not boolean
    u64 loc;
    u64 des;
    bool conditional;
};

void asm_init(const char* asm_file_name);
void advance_to_mode(void);

jmp get_next_jmp(u64 current_ip);

#endif