#ifndef ASM_PARSE_INTERNAL_H_
#define ASM_PARSE_INTERNAL_H_

#include <stdio.h>
#include <stdbool.h>

#include <string>

#include "types.h"

typedef enum trace_type {
    BLOCK,
    JXX,
    JXX_LDST,
    JMP,
    LABEL,
    UPDATE,
    IPT_START,
    IPT_STOP,
    BLOCK_SIZE
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

        struct { /* jxx_ldst */
            u64 loc;
            u64 des;
        } jxx_ldst;

        struct { /* label */
            u64 loc;
            u32 id;
        } label;

        struct { /* Update */
            u64 loc;
            u64 new_des;
        } update;

        u64 block_size; /* Block Size */
        
    } data;
} trace_element;


static bool parse_block(std::string& line, trace_element& out);
static bool parse_block_size(std::string& line, trace_element& out);
static bool parse_jmp(std::string& line, trace_element& out);
static bool parse_jxx(std::string& line, trace_element& out);
static bool parse_update(std::string& line, trace_element& out);
static bool parse_label(std::string& line, trace_element& out);
static bool parse_ipt_start(std::string& line, trace_element& out);
static bool parse_ipt_stop(std::string& line, trace_element& out);
static bool parse_jxx_ldst(std::string& line, trace_element& out);

#endif