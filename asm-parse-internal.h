#ifndef ASM_PARSE_INTERNAL_H_
#define ASM_PARSE_INTERNAL_H_

#include <stdio.h>
#include <stdbool.h>

#include <string>
#include <map>

#include "types.h"
#include "asm-parse.h"
#include "asm-types.h"

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

static void print_trace_element(trace_element& elmnt);

static u64 parse_ip(std::string& line, u32& pos);
static u64 parse_id(std::string& line, u32& pos);

#endif