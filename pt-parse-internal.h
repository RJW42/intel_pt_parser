#ifndef PT_PARSE_INTERNAL_H_
#define PT_PARSE_INTERNAL_H_

#include "pt-parse-types.h"

#include <stdbool.h>

#include <vector>
#include <optional>
#include <stack>

static unsigned long get_mapping(unsigned long host_pc);

static void log_basic_block(unsigned long id);

static void print_packet_debug(
    pt_packet packet, u64& pad_count
);

static void update_current_ip(
    u64& current_ip, u64 new_ip, 
    u64 qemu_caller_ip, u64 qemu_memory_offset,
    bool& tracing_qemu_code, bool& tracing_jit_code
);

static void follow_asm(
    std::optional<tnt_packet_data> tnt_packet, u64& current_ip, 
    u64 qemu_return_ip, u64 qemu_caller_ip, 
    u64 qemu_memory_offset, u64& qemu_call_adr, 
    bool& next_tip_is_qemu_call, std::stack<u64>& call_stack, 
    bool& tracing_qemu_code, bool& tracing_jit_code
);

static std::optional<pt_instruction> get_next_instr(
    u64 current_ip, u64 qemu_memory_offset, 
    bool tracing_qemu_code, bool tracing_jit_code
);

static inline pt_instruction_type jit_to_pt_instr_type(
    jit_asm_type type
);

static inline pt_instruction_type src_to_pt_instr_type(
    src_asm_instruction type
);

static void load_output_file(char *file_name);
static void load_trace_file(char *file_name);
static void load_mapping_file(char *file_name);

static void parse();

static pt_packet get_next_packet(u64 curr_ip);
static std::optional<pt_packet> parse_short_tnt(void);
static std::optional<pt_packet> parse_long_tnt(void);
static std::optional<pt_packet> parse_tip(u64 curr_ip);
static std::optional<pt_packet> parse_pip(void);
static std::optional<pt_packet> parse_mode(void);
static std::optional<pt_packet> parse_trace_stop(void);
static std::optional<pt_packet> parse_cbr(void);
static std::optional<pt_packet> parse_tsc(void);
static std::optional<pt_packet> parse_mtc(void);
static std::optional<pt_packet> parse_tma(void);
static std::optional<pt_packet> parse_vmcs(void);
static std::optional<pt_packet> parse_ovf(void);
static std::optional<pt_packet> parse_cyc(void);
static std::optional<pt_packet> parse_psb(void);
static std::optional<pt_packet> parse_psb_end(void);
static std::optional<pt_packet> parse_mnt(void);
static std::optional<pt_packet> parse_pad(void);
static std::optional<pt_packet> parse_ptw(void);
static std::optional<pt_packet> parse_exstop(void);
static std::optional<pt_packet> parse_mwait(void);
static std::optional<pt_packet> parse_pwre(void);
static std::optional<pt_packet> parse_pwrx(void);
static std::optional<pt_packet> parse_bbp(void);
static std::optional<pt_packet> parse_bip(void);
static std::optional<pt_packet> parse_bep(void);
static std::optional<pt_packet> parse_cfe(void);
static std::optional<pt_packet> parse_evd(void);
static pt_packet parse_unkown(void);

static std::optional<pt_tip_type> parse_tip_type(unsigned char *buffer);
static std::optional<u8> parse_tip_ip_use(u8 ip_bits);

static void print_packet(const pt_packet& packet);
static void print_tip(const pt_packet& packet);
static void print_tnt(const pt_packet& packet);
#endif