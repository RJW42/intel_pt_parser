#ifndef PT_PARSE_TYPES_H_
#define PT_PARSE_TYPES_H_

#include "types.h"
#include "asm-types.h"

#include <stdbool.h>

#include <vector>
#include <bitset>


enum pt_packet_type {  
    TNT,
    TIP,
    TIP_OUT_OF_CONTEXT,
    PIP,
    MODE,
    TRACE_STOP,
    CBR,
    TSC,
    MTC,
    TMA,
    VMCS,
    OVF,
    CYC,
    PSB,
    PSBEND,
    MNT,
    PAD,
    PTW,
    EXSTOP,
    MWAIT,
    PWRE,
    PWRX,
    BBP,
    BIP,
    BEP,
    CFE,
    EVD,
    UNKOWN
};


enum pt_tip_type {
    TIP_TIP,
    TIP_PGE,
    TIP_PGD,
    TIP_FUP,
};


struct tnt_packet_data {
    u8 size;
    std::bitset<47> tnt;
};


struct tip_packet_data {
    pt_tip_type type;
    u8 ip_bits;
    u8 last_ip_use;
    u64 ip_buffer;
    u64 ip;

    tip_packet_data(
        pt_tip_type type, u8 ip_bits, 
        u8 last_ip_use, u64 ip_buffer, u64 ip
    ) :
        type(type), ip_bits(ip_bits), 
        last_ip_use(last_ip_use), ip_buffer(ip_buffer), ip(ip) 
    {};
};


struct unkown_packet_data {
    u8 byte;

    unkown_packet_data(u8 byte) : 
        byte(byte) {};
};


struct pt_packet {
    pt_packet_type type;
    union 
    {
        tnt_packet_data tnt_data;
        tip_packet_data tip_data;
        unkown_packet_data unkown_data;
    };

    pt_packet(pt_packet_type type) : 
        type(type) {};
    pt_packet(unkown_packet_data unkown_data) : 
        type(UNKOWN), unkown_data(unkown_data) {};
    pt_packet(tnt_packet_data tnt_data) :
        type(TNT), tnt_data(tnt_data) {};
    pt_packet(tip_packet_data tip_data) :
        type(TIP), tip_data(tip_data) {};
};



enum pt_instruction_type {
    PT_JMP,
    PT_JXX,
    PT_CALL
};


struct pt_instruction {
    pt_instruction_type type;
    bool is_qemu_src;
    u64 loc;
    u64 des; /* des of jump / call, empty for ret*/
    bool is_breakpoint;


    pt_instruction(
        pt_instruction_type type, bool is_qemu_src, u64 loc, u64 des
    ) : type(type), is_qemu_src(is_qemu_src), loc(loc), des(des),
        is_breakpoint(false) {};
    pt_instruction(
        pt_instruction_type type, bool is_qemu_src, u64 loc, u64 des, 
        bool is_breakpoint
    ) : type(type), is_qemu_src(is_qemu_src), loc(loc), des(des),
        is_breakpoint(is_breakpoint) {};
    pt_instruction() {};
};


struct pt_state {
    /* The current instruction poitner (ip) value */
    u64 current_ip;

    /* The last guest ip found */
    u64 previous_guest_ip;

    /* Store the last TIP ip value. This is used for 
     * for generating the next value */
    u64 last_tip_ip;

    /* If this ip is seen it indicates that intel pt 
     * has been started, so we can advance asm */
    u64 qemu_caller_ip;

    /* If this ip is seen it indicates that we are 
     * about to leave JITed code and return to qemu */
    u64 qemu_return_ip;

    /* Store the number of pads seen. Used for debugging */
    u64 pad_count;

    /* The ip of the breakpoint function */
    u64 breakpoint_ip;

    /* The ip in jitted code to jump to after a breakpoint call */
    u64 breakpoint_return_ip;

    /* Store the last seen intel pt packet */
    pt_packet *last_packet;

    /* Keeps track if we are currently waiting for a psbend */
    bool in_psb;

    /* Keeps track if we have seen an fup packet and are 
      * waiting to bind that packet */
    bool in_fup;

    /* Keeps track if the previous packet was a mode. This is used 
     * by fup packets to check if it binds to that mode */
    bool last_was_mode;

    /* Keeps track if the previous packet was a OVF. This is used 
     * by fup packets to indicate a reset after an overflow */
    bool last_was_ovf;

    /* Keeps track if we are currently tracing jit code and 
     * if we are not tracing jit code then we have no asm */
    bool tracing_jit_code;

    /* Keeps track if the last tip call was a breakpoint call */
    bool last_tip_was_breakpoint;

    /* Keeps track if the last tnt lead to a call to the breakpoint */
    bool next_tip_is_breakpoint;

    /* Keep track if the last ip that was reached by following an un
     * -conditional jump. We need to know this as qemu may send us a
     * fup that takes us back in time */
    bool last_ip_was_reached_by_u_jump;

    /* Ip used for the situation described above */
    bool last_ip_had_mapping;

    /* We need to store this for a simmilar reason to the last ip 
     * reached by u_jump*/
    bool last_ip_was_reached_by_tip;

    /* The file to output the trace too */
    FILE* out_file;

    /* The file to read the pt data from */
    FILE* trace_data;

    /* Track the amount of data needing to be parced*/
    u64 size;

    /* Tracck the current offset in the trace file */
    u64 offset;

    /* Store the current state of the assembly code */
    asm_state asm_parsing_state;

    pt_state() : 
        current_ip(0),
        previous_guest_ip(0),
        last_tip_ip(0),
        qemu_caller_ip(0),
        qemu_return_ip(0),
        pad_count(0), 
        breakpoint_ip(0),
        breakpoint_return_ip(0),
        last_packet(NULL),
        in_psb(false),
        in_fup(false),
        last_was_mode(false),
        last_was_ovf(false),
        tracing_jit_code(false),
        last_tip_was_breakpoint(false),
        next_tip_is_breakpoint(false),
        last_ip_was_reached_by_u_jump(false),
        last_ip_had_mapping(false),
        last_ip_was_reached_by_tip(false),
        out_file(NULL),
        trace_data(NULL),
        size(0),
        offset(0) {};
};

#endif