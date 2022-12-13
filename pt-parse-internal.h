#ifndef PT_PARSE_INTERNAL_H_
#define PT_PARSE_INTERNAL_H_

#include "pt-parse-types.h"
#include "asm-types.h"

#include <stdbool.h>

#include <vector>
#include <optional>
#include <stack>

static void log_basic_block(
    pt_state& state, u64 id
);

static void print_packet_debug(
    pt_packet& packet, pt_state& state
);

static void update_current_ip(
    pt_state& state, u64 ip
);
static void update_current_ip_from_destination(
    pt_state& state, jmp_destination& des
);

static void handle_tip(pt_state& state);

static void follow_asm(pt_state& state);

static jit_asm_instruction* get_next_instr(
    pt_state& state, u64 ip
);

static bool can_follow_asm(pt_state& state);

static void load_output_file(pt_state& state, const char *file_name);
static void load_trace_file(pt_state& state, const char *file_name);

static void parse(pt_state& state);

static std::optional<pt_packet> try_get_next_packet(pt_state& state);

static inline pt_packet get_next_packet(pt_state& state, u64 curr_ip);
static inline bool parse_short_tnt(pt_state& state, pt_packet& packet);
static inline bool parse_long_tnt(pt_state& state, pt_packet& packet);
static inline bool parse_tip(pt_state& state, pt_packet& packet, u64 curr_ip);
static inline bool parse_pip(pt_state& state, pt_packet& packet);
static inline bool parse_mode(pt_state& state, pt_packet& packet);
static inline bool parse_trace_stop(pt_state& state, pt_packet& packet);
static inline bool parse_cbr(pt_state& state, pt_packet& packet);
static inline bool parse_tsc(pt_state& state, pt_packet& packet);
static inline bool parse_mtc(pt_state& state, pt_packet& packet);
static inline bool parse_tma(pt_state& state, pt_packet& packet);
static inline bool parse_vmcs(pt_state& state, pt_packet& packet);
static inline bool parse_ovf(pt_state& state, pt_packet& packet);
static inline bool parse_cyc(pt_state& state, pt_packet& packet);
static inline bool parse_psb(pt_state& state, pt_packet& packet);
static inline bool parse_psb_end(pt_state& state, pt_packet& packet);
static inline bool parse_mnt(pt_state& state, pt_packet& packet);
static inline bool parse_pad(pt_state& state, pt_packet& packet);
static inline bool parse_ptw(pt_state& state, pt_packet& packet);
static inline bool parse_exstop(pt_state& state, pt_packet& packet);
static inline bool parse_mwait(pt_state& state, pt_packet& packet);
static inline bool parse_pwre(pt_state& state, pt_packet& packet);
static inline bool parse_pwrx(pt_state& state, pt_packet& packet);
static inline bool parse_bbp(pt_state& state, pt_packet& packet);
static inline bool parse_bip(pt_state& state, pt_packet& packet);
static inline bool parse_bep(pt_state& state, pt_packet& packet);
static inline bool parse_cfe(pt_state& state, pt_packet& packet);
static inline bool parse_evd(pt_state& state, pt_packet& packet);
static inline void parse_unkown(pt_state& state, pt_packet& packet);

static std::optional<pt_tip_type> parse_tip_type(u8 *buffer);
static std::optional<u8> parse_tip_ip_use(u8 ip_bits);

static void print_packet(const pt_packet& packet);
static void print_tip(const pt_packet& packet);
static void print_tnt(const pt_packet& packet);
#endif