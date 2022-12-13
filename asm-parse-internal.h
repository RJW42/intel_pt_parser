#ifndef ASM_PARSE_INTERNAL_H_
#define ASM_PARSE_INTERNAL_H_

#include <stdio.h>
#include <stdbool.h>

#include <string>

#include "types.h"
#include "asm-parse.h"
#include "asm-types.h"

#include "robbin_hood.h"

struct advance_state {
    /* Track the current tb being parced */
    translated_block *current_block;
    
    /* Track jumps waiting for a label*/
    robin_hood::unordered_map<u32, trace_element> unset_jxx; 

    /* The current element in the asm log being delt with */
    trace_element current_element;

    advance_state() : current_block(NULL) {};
};



static inline bool parse_trace_element(std::string& line, trace_element& out);
static inline bool parse_block(std::string& line, trace_element& out);
static inline bool parse_block_size(std::string& line, trace_element& out);
static inline bool parse_jmp(std::string& line, trace_element& out);
static inline bool parse_jxx1(std::string& line, trace_element& out);
static inline bool parse_jxx2(std::string& line, trace_element& out);
static inline bool parse_update(std::string& line, trace_element& out);
static inline bool parse_label(std::string& line, trace_element& out);
static inline bool parse_ipt_start(std::string& line, trace_element& out);
static inline bool parse_ipt_stop(std::string& line, trace_element& out);
static inline bool parse_jxx_ldst(std::string& line, trace_element& out);
static inline bool parse_call(std::string& line, trace_element& out);


static inline void handle_block(asm_state& global_state, advance_state& state);
static inline void handle_block_size(asm_state& global_state, advance_state& state);
static inline void handle_jmp(asm_state& global_state, advance_state& state);
static inline void handle_computed_jmp(asm_state& global_state, advance_state& state);
static inline void handle_jxx(asm_state& global_state, advance_state& state);
static inline void handle_jxx_ldst(asm_state& global_state, advance_state& state);
static inline void handle_call(asm_state& global_state, advance_state& state);
static inline void handle_update(asm_state& global_state, advance_state& state);
static inline void handle_label(asm_state& global_state, advance_state& state);
static inline void handle_ipt_stop(asm_state& global_state, advance_state& state);
static inline void handle_ipt_start(asm_state& global_state, advance_state& state);


static inline void set_jump_destination(
    asm_state& global_state, advance_state& state, jmp_destination& destination
);
static inline void update_jump_desitation(
    asm_state& global_state, advance_state& state, 
    jmp_destination& destination, u64 new_destination
);
static inline jit_asm_instruction* get_next_jump_within_block_after_ip(
    translated_block* block, u64 start_ip
);

static void print_trace_element(trace_element& elmnt);

static u64 parse_ip(std::string& line, u32& pos);
static u64 parse_id(std::string& line, u32& pos);



#endif