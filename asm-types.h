#ifndef ASM_TYPES_H_
#define ASM_TYPES_H_

#include <fstream>
#include <iostream>
#include <map>


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


enum trace_type {
    BLOCK,
    JXX,
    JXX_LDST,
    CALL,
    JMP,
    LABEL,
    UPDATE,
    IPT_START,
    IPT_STOP,
    BLOCK_SIZE
};

struct trace_element {
    trace_type type;
    union {
        u64 block_ip; /* block */
        u64 block_size; /* Block Size */

        struct { 
            u64 loc;

            union {
               u64 des; /* jmp, jxx_ldst */
               u32 id;  /* jxx, label */
               u64 new_des; /* Update */

               struct { /* Call */
                  u64 qemu_des;
                  bool is_breakpoint;
               };
            };
        };
    };
};


struct basic_block {
    u64 start_ip;
    u64 end_ip;
    u64 size;
    std::map<u64, jit_asm_instruction*> instructions;
};


struct asm_state {
   /* A map from start addresss to each basic block */
   std::map<u64, basic_block*> blocks;

   /* A complete list of all instructions at a given address */
   std::map<u64, jit_asm_instruction*> instructions;

   /* File storing assmebly code needing parsed */
   std::ifstream asm_file;

   asm_state() {}
};

#endif