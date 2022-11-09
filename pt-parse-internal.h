#ifndef PT_PARSE_INTERNAL_H_
#define PT_PARSE_INTERNAL_H_

#include "pt-parse-types.h"

#include <stdbool.h>
#include <vector>

static unsigned long get_mapping(unsigned long host_pc);
static void save_ip_mapping(unsigned long host_ip);

static void log_basic_block(unsigned long id);

static void load_output_file(char *file_name);
static void load_trace_file(char *file_name);
static void load_mapping_file(char *file_name);
static void parse();

static bool parse_tnt(std::vector<bool>& tnt);
static bool parse_tip(bool& use_next_tnt);
static bool parse_pip(void);
static bool parse_mode(void);
static bool parse_trace_stop(void);
static bool parse_cbr(void);
static bool parse_tsc(void);
static bool parse_mtc(void);
static bool parse_tma(void);
static bool parse_vmcs(void);
static bool parse_ovf(void);
static bool parse_cyc(void);
static bool parse_psb(bool& in_psb_start);
static bool parse_psb_end(bool& in_psb_start);
static bool parse_mnt(void);
static bool parse_pad(void);
static bool parse_ptw(void);
static bool parse_exstop(void);
static bool parse_mwait(void);
static bool parse_pwre(void);
static bool parse_pwrx(void);
static bool parse_bbp(void);
static bool parse_bip(void);
static bool parse_bep(void);
static bool parse_cfe(void);
static bool parse_evd(void);

static bool parse_tip_base(unsigned char *buffer);
static bool parse_tip_pge(unsigned char *buffer);
static bool parse_tip_pgd(unsigned char *buffer);
static bool parse_tip_fup(unsigned char *buffer);

#endif