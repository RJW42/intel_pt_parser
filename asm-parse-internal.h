#ifndef ASM_PARSE_INTERNAL_H_
#define ASM_PARSE_INTERNAL_H_

#include <stdio.h>
#include <stdbool.h>

#include "types.h"

typedef enum trace_type {
    BLOCK,
    JXX,
    JMP,
    LABEL,
    UPDATE,
    IPT_START,
    IPT_STOP
} trace_type;


typedef struct trace_element {
    trace_type type;
    union {
        u64 block_ip; /* block */

        struct { /* jmp */
            u64 loc;
            u64 des;
        } jmp;
        
        struct { /* jxx */
            u64 loc;
            u32 id;
        } jxx;

        struct { /* label */
            u64 loc;
            u32 id;
        } label;

        struct { /* Update */
            u64 loc;
            u64 new_des;
        } update;
    } data;
} trace_element;

#endif