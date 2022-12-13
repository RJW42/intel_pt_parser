#ifndef ASM_TYPES_H_
#define ASM_TYPES_H_

#include <fstream>
#include <iostream>

#include <map>
#include <unordered_map>

struct translated_block;
struct jit_asm_instruction;

enum jmp_destination_type {
    RETURN_TO_QEMU,
    NEW_BLOCK,
    SAME_BLOCK,
    COMPUTED,
};


struct jmp_destination {
    jmp_destination_type type;
    
    /* Note: for a computed jump the destination is 0 */
    u64 ip; 

    union { /* Can't forward decalre types so needs to be void* */
        translated_block* next_block; /* New Block */
        jit_asm_instruction* next_instr; /* Same Block */
    };
};


enum jit_asm_type {
    JIT_JXX,
    JIT_JMP,
    JIT_CALL
};


struct jit_asm_instruction {
    translated_block *block;
    jit_asm_type type;
    u64 ip;

    union {
        bool is_breakpoint; /* CALL */
        jmp_destination des; /* JMP */
        struct { /* JXX */
            jmp_destination taken_des;
            jmp_destination not_taken_des;
        };
    };
};


struct translated_block {
    u64 start_ip;
    u64 end_ip;
    u64 size;
    u64 guest_ip;
    std::map<u64, jit_asm_instruction*> instructions;
};


enum trace_type {
    BLOCK,
    JXX,
    JXX_LDST,
    CALL,
    JMP,
    COMPUTED_JMP,
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


struct asm_state {
   /* A map from start addresss to each basic block */
   std::map<u64, translated_block*> ordered_blocks;
   std::unordered_map<u64, translated_block*> unordered_blocks;

   /* A complete list of all instructions at a given address 
    * storing them as both unordered and ordered map helps lookup times */
   std::map<u64, jit_asm_instruction*> ordered_instructions;
   std::unordered_map<u64, jit_asm_instruction*> unordered_instructions;

   /* File storing assmebly code needing parsed */
   std::ifstream asm_file;

   /* This is the location in which tb's jump too, to 
    * return back to qemu code. It is always the last 
    * direct jump in a translated block */
   u64 qemu_return_ip;

   asm_state() : qemu_return_ip(0) {}
};

#endif