#ifndef PT_PARSE_TYPES_H_
#define PT_PARSE_TYPES_H_

#include "types.h"

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


#endif