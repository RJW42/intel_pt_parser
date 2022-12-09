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
    pt_packet& packet, pt_state& state
);

static void update_current_ip(
    pt_state& state, u64 ip
);

static void handle_tip(pt_state& state);

static void follow_asm(pt_state& state);

static std::optional<pt_instruction> get_next_instr(
    pt_state& state, u64 ip
);

static pt_instruction_type jit_to_pt_instr_type(
    jit_asm_type type
);

static bool can_follow_asm(pt_state& state);

static void load_output_file(char *file_name);
static void load_trace_file(char *file_name);
static void load_mapping_file(char *file_name);

static void parse(void);

static std::optional<pt_packet> try_get_next_packet(void);

static inline pt_packet get_next_packet(u64 curr_ip);
static inline bool parse_short_tnt(pt_packet& packet);
static inline bool parse_long_tnt(pt_packet& packet);
static inline bool parse_tip(pt_packet& packet, u64 curr_ip);
static inline bool parse_pip(pt_packet& packet);
static inline bool parse_mode(pt_packet& packet);
static inline bool parse_trace_stop(pt_packet& packet);
static inline bool parse_cbr(pt_packet& packet);
static inline bool parse_tsc(pt_packet& packet);
static inline bool parse_mtc(pt_packet& packet);
static inline bool parse_tma(pt_packet& packet);
static inline bool parse_vmcs(pt_packet& packet);
static inline bool parse_ovf(pt_packet& packet);
static inline bool parse_cyc(pt_packet& packet);
static inline bool parse_psb(pt_packet& packet);
static inline bool parse_psb_end(pt_packet& packet);
static inline bool parse_mnt(pt_packet& packet);
static inline bool parse_pad(pt_packet& packet);
static inline bool parse_ptw(pt_packet& packet);
static inline bool parse_exstop(pt_packet& packet);
static inline bool parse_mwait(pt_packet& packet);
static inline bool parse_pwre(pt_packet& packet);
static inline bool parse_pwrx(pt_packet& packet);
static inline bool parse_bbp(pt_packet& packet);
static inline bool parse_bip(pt_packet& packet);
static inline bool parse_bep(pt_packet& packet);
static inline bool parse_cfe(pt_packet& packet);
static inline bool parse_evd(pt_packet& packet);
static inline void parse_unkown(pt_packet& packet);

static std::optional<pt_tip_type> parse_tip_type(unsigned char *buffer);
static std::optional<u8> parse_tip_ip_use(u8 ip_bits);

static void print_packet(const pt_packet& packet);
static void print_tip(const pt_packet& packet);
static void print_tnt(const pt_packet& packet);
#endif