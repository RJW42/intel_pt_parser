#ifndef PT_PARSE_TYPES_H_
#define PT_PARSE_TYPES_H_

#include "types.h"

#include <stdbool.h>

#include <vector>


enum pt_packet_type {  
    TIP,
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
    EVD
};

enum pt_tip_type {
    TIP_TIP,
    TIP_PGE,
    TIP_PGD,
    TIP_FUP
};


struct tnt_packet_data {
    std::vector<bool> tnt;
};


struct tip_packet_data {
    pt_tip_type type;
    u8 ip_bits;
    u8 last_ip_use;
    u8 *ip_buffer;
};


struct pt_packet {
    pt_packet_type type;
    union 
    {
        tnt_packet_data tnt_data;
        tip_packet_data tip_data;
    };
};


#endif