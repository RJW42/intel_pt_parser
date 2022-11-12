#include "types.h"

#include "asm-parse.h"
#include "qemu-source-parse.h"

#include "pt-parse-types.h"
#include "pt-parse-internal.h"
#include "pt-parse-oppcode.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <vector>
#include <unordered_map>
#include <iostream>
#include <ostream>
#include <optional>
#include <stack>

static FILE* out_file;
static FILE* trace_data;
static u64 offset;
static u64 size;
static std::unordered_map<u64, u64> host_ip_to_guest_ip;
static bool use_asm;

#define DEBUG_MODE_

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 


#define LEFT(n) ((size - offset) >= n) // TODO: Check this >=
#define ADVANCE(n) offset += n
#define REVERT(n) offset -= n
#define GET_BYTES(buffer, size) do {\
    fseek(trace_data, offset, SEEK_SET); \
    fread(buffer, size, 1, trace_data); \
}while(0)
#define INIT_BUFFER(name, size) \
    unsigned char name[size]; \
    GET_BYTES(name, size)

#define LOWER_BITS(value, n) (value & ((1 << n) - 1))
#define MIDDLE_BITS(value, uppwer, lower) (value & (((1 << uppwer) - 1) << lower))

#define RETURN_IF(x) \
    packet = x(); \
    if(packet) return *packet
#define RETURN_IF_2(x, y) \
    packet = x(y); \
    if(packet) return *packet

int main() 
{
    // TODO: change this to args
    // char trace_file_name[] = "traces/hw1-prog0-trace-dump.pt";
    // char mapping_file_name[] = "traces/hw1-prog0-mapping-data.mpt";
    // char trace_out_file_name[] = "traces/trace-out.txt";

    char asm_file_name[] = "trace_hw2/asm-trace.txt";
    char trace_file_name[] =     "trace_hw2/trace-dump.pt";
    char mapping_file_name[] =   "trace_hw2/mapping-data.mpt";
    char trace_out_file_name[] = "trace_hw2/trace-dump.txt";
    char qemu_source_file_name[] = "/home/rjw24/Downloads/qemu-asm.txt";

    use_asm = true;

    qemu_source_init(qemu_source_file_name, asm_file_name);
    asm_init(asm_file_name);

    load_output_file(trace_out_file_name);
    load_mapping_file(mapping_file_name);
    load_trace_file(trace_file_name);
    
    parse();

    // fclose(out_file);
}


void parse(void) 
{
#ifdef DEBUG_MODE_
    printf(" -------- Intel PT Start ---------- \n\n");
    printf("Size: %lu\n", size);
#endif
    u64 qemu_caller_ip = 0x55E8347EA1D6;
    u64 qemu_return_ip = 0x7F99B7F7F018;
    u64 qemu_memory_offset = 0;

    u64 current_ip = 0;
    u64 pad_count = 0;
    bool in_psb = false;
    bool follow_next_tnt = false;

    std::stack<u64> call_stack;


    while(offset < size) {
        // Parse The Current Packet
        pt_packet packet = get_next_packet(current_ip);
        print_packet_debug(packet, pad_count);

        // Handle This Packet
        if(packet.type == TIP) {
            // Update Current IP
            update_current_ip(
                current_ip, packet.tip_data.ip, 
                qemu_caller_ip, follow_next_tnt
            );
        } else if(packet.type == PSB) {
            in_psb = true;
        } else if(packet.type == PSBEND) {
            in_psb = false;
        } else if(packet.type == TNT && follow_next_tnt) {
            follow_tnt_packet(
                packet, current_ip, qemu_return_ip, qemu_memory_offset
                qemu_caller_ip, follow_next_tnt, call_stack
            );
        } 
    }
}


static inline void follow_tnt_packet(
    pt_packet packet, u64& current_ip, u64 qemu_return_ip, 
    u64 qemu_caller_ip, u64& qemu_memory_offset, bool& follow_next_tnt,
    std::stack<u64>& call_stack
) {
    u64 ip = current_ip;
    jit_asm_instruction j;
    bool found_mapping;

    for(int i = 0; i < packet.tnt_data.size; i++) {
        // Get the next conditional jump
        for(j = get_next_jit_instr(ip); j.type != JIT_JXX; j = get_next_jit_instr(ip)) {
            printf("  TU. JMP: %lX -> %lX\n", j.loc, j.des);
            ip = j.des;
            
            if(ip == qemu_return_ip) {
                printf("    JMP out of bounds\n");
                follow_next_tnt = false;
                return;                
            };

            update_current_ip(current_ip, ip, qemu_caller_ip, found_mapping);
        }

        // Check if this conditional jump is taken
        if(!packet.tnt_data.tnt[i]) {
            // Not Taken
            printf("  NT. JMP: %lX -> %lX\n", j.loc, j.des);
            ip = j.loc + 1;
            current_ip = ip;
            //update_current_ip(current_ip, ip, found_mapping);
            continue;
        }       

        // Jump is taken update ip 
        if(ip == qemu_return_ip) {
            printf("    JMP out of bounds\n");
            follow_next_tnt = false;
            return;                
        };

        printf("  TC. JMP: %lX -> %lX\n", j.loc, j.des);
        ip = j.des;
        update_current_ip(current_ip, ip, qemu_caller_ip, found_mapping);
    }
}


static inline void update_current_ip(
    u64& current_ip, u64& new_ip, 
    u64 qemu_caller_ip, bool& found_mapping
) {
    current_ip = new_ip;
    u64 guest_ip = get_mapping(current_ip);

    if(current_ip == qemu_caller_ip) {
        advance_to_mode();
    }
    
    if(guest_ip == 0) {
        found_mapping = ip_inside_block(current_ip);
        return;
    } 

    log_basic_block(guest_ip);
    found_mapping = true;

#ifdef DEBUG_MODE_
        printf("    Host IP: 0x%lX -> Guest IP: 0x%lX\n", current_ip, guest_ip);
#endif
}


static inline void print_packet_debug(pt_packet packet, u64& pad_count)
{
#ifdef DEBUG_MODE_
    if(packet.type == PAD) {
        pad_count++;
        return;
    }

    if(pad_count > 0) {
        printf("PAD x %lu\n", pad_count);
        pad_count = 0;
    }

    print_packet(packet);
#endif
}


/* ***** Parsing ***** */

static pt_packet get_next_packet(u64 curr_ip)
{
    std::optional<pt_packet> packet;
    
    RETURN_IF(parse_short_tnt);
    RETURN_IF(parse_long_tnt);
    RETURN_IF_2(parse_tip, curr_ip);
    RETURN_IF(parse_pip);
    RETURN_IF(parse_mode);
    RETURN_IF(parse_trace_stop);
    RETURN_IF(parse_cbr);
    RETURN_IF(parse_tsc);
    RETURN_IF(parse_mtc);
    RETURN_IF(parse_tma);
    RETURN_IF(parse_vmcs);
    RETURN_IF(parse_ovf);
    RETURN_IF(parse_cyc);
    RETURN_IF(parse_psb);
    RETURN_IF(parse_psb_end);
    RETURN_IF(parse_mnt);
    RETURN_IF(parse_pad);
    RETURN_IF(parse_ptw);
    RETURN_IF(parse_exstop);
    RETURN_IF(parse_mwait);
    RETURN_IF(parse_pwre);
    RETURN_IF(parse_pwrx);
    RETURN_IF(parse_bbp);
    RETURN_IF(parse_bip);
    RETURN_IF(parse_bep);
    RETURN_IF(parse_cfe);
    RETURN_IF(parse_evd);

    return parse_unkown();
}


static std::optional<pt_packet> parse_short_tnt(void)
{
    // Attempt to pase a short TNT packet
    if(!LEFT(SHORT_TNT_PACKET_LENGTH))
        return std::nullopt;
    
    char byte;
    GET_BYTES(&byte, 1);

    if(LOWER_BITS(byte, 1) != 0) 
        return std::nullopt;

    int start_bit = 6;

    for(; start_bit > 0; start_bit--) {
        if(byte & (0b10 << start_bit)) {
            break;
        }
    }

    if(start_bit == 0) return std::nullopt;

    // Is Short TNT packet. Parse it's data
    tnt_packet_data data;
    data.size = start_bit;

    for(int i = start_bit - 1; i >= 0; i--) {
        bool taken = (byte & (0b10 << i));
        data.tnt[start_bit - (i + 1)] = taken;
    }
    
    ADVANCE(1);
    return { pt_packet(data) };
}

static std::optional<pt_packet> parse_long_tnt(void)
{
     // Attempt to parse a Long TNT packet 
    if(!LEFT(LONG_TNT_PACKET_LENGTH)) 
        return std::nullopt;

    INIT_BUFFER(buffer, LONG_TNT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != LONG_TNT_OPPCODE) 
        return std::nullopt;

    printf("LONG TNT NOT IMPLEMENTED\n");
    exit(EXIT_FAILURE);

    ADVANCE(LONG_TNT_PACKET_LENGTH);

    // TODO: implement 
    return {};
}


static std::optional<pt_packet> parse_tip(u64 curr_ip) 
{
    if(!LEFT(TIP_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, TIP_PACKET_LENGTH);

    // Get the type of this packet 
    auto type = parse_tip_type(buffer);

    if(!type) return std::nullopt;

    // Check if the ip is within context
    u8 ip_bits = buffer[0] >> 5;

    if(ip_bits == 0b000) {
        ADVANCE(1);
        return { pt_packet(TIP_OUT_OF_CONTEXT) };
    }

    // ip in context get compression status
    auto last_ip_use = parse_tip_ip_use(ip_bits);
    if(!last_ip_use) return std::nullopt;

    // Create ip buffer
    u64 ip_buffer = 0;
    u64 ip = curr_ip;

    for(int i = 0; i < 8; i++) {
        u8 byte = i >= *last_ip_use ? 
            buffer[8 - i] : 
            (curr_ip >> ((7 - i) * 8)) & 0xff;

        ip = (ip << 8) | byte;

        if(i >= *last_ip_use)
            ip_buffer = (ip_buffer << 8) | byte;
    }

    tip_packet_data data(*type, ip_bits, *last_ip_use, ip_buffer, ip);

    // Finished return packet
    ADVANCE(TIP_PACKET_LENGTH - *last_ip_use);

    return {pt_packet(data)};
}  


static std::optional<pt_tip_type> parse_tip_type(unsigned char *buffer)
{
    unsigned char bits = LOWER_BITS(buffer[0], TIP_OPPCODE_LENGTH_BITS);

    switch (bits) {
    case TIP_BASE_OPPCODE:
        return { TIP_TIP };
    case TIP_PGE_OPPCODE:
        return { TIP_PGE };
    case TIP_PGD_OPPCODE:
        return { TIP_PGD };
    case TIP_FUP_OPPCODE:
        return { TIP_FUP };
    default:
        return std::nullopt;
    }
}


static std::optional<u8> parse_tip_ip_use(u8 ip_bits)
{
    switch (ip_bits) {
    case 0b001:
        return {6};
        break;
    case 0b010:
        return {4};
        break;
    case 0b011:
#ifdef DEBUG_MODE_ 
        printf("TIP - Not implemented\n");
#endif
        return std::nullopt;
        break;
    case 0b100:
        return {2};
        break;
    case 0b110:
        return {0};
        break;
    default:
#ifdef DEBUG_MODE_ 
        printf("TIP - Reserved bits\n");
#endif
        return std::nullopt;
    }
}


static std::optional<pt_packet> parse_pip(void)
{
    if(!LEFT(PIP_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, PIP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PIP_OPPCODE)
        return std::nullopt;

    ADVANCE(PIP_PACKET_LENGTH);

    return { pt_packet(PIP) };
}


static std::optional<pt_packet> parse_mode(void)
{
    if(!LEFT(MODE_PACKET_LENGTH))    
        return std::nullopt;
    
    INIT_BUFFER(buffer, MODE_PACKET_LENGTH);

    if(buffer[0] != MODE_OPPCODE)
        return std::nullopt;

    // Todo: Parse the two different types of mode

    ADVANCE(MODE_PACKET_LENGTH);

    return { pt_packet(MODE) };
}


static std::optional<pt_packet> parse_trace_stop(void) 
{
    if(!LEFT(TRACE_STOP_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, TRACE_STOP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != TRACE_STOP_OPPCODE)
        return std::nullopt;
    
    ADVANCE(TRACE_STOP_PACKET_LENGTH);

    return { pt_packet(TRACE_STOP) };
}


static std::optional<pt_packet> parse_cbr(void) 
{
    if(!LEFT(CBR_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, CBR_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != CBR_OPPCODE)
        return std::nullopt;

    ADVANCE(CBR_PACKET_LENGTH);

    return { pt_packet(CBR) };
}


static std::optional<pt_packet> parse_tsc(void) 
{
    if(!LEFT(TSC_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, TSC_PACKET_LENGTH);

    if(buffer[0] != TSC_OPPCODE)
        return std::nullopt;

    ADVANCE(TSC_PACKET_LENGTH);

    return { pt_packet(TSC) };
}


static std::optional<pt_packet> parse_mtc(void)
{
    if(!LEFT(MTC_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, MTC_PACKET_LENGTH);

    if(buffer[0] != MTC_OPPCODE)
        return std::nullopt;

    ADVANCE(TSC_PACKET_LENGTH);

    return { pt_packet(MTC) };
}


static std::optional<pt_packet> parse_tma(void)
{
    if(!LEFT(TMA_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, TMA_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != TMA_OPPCODE) 
        return std::nullopt;
    
    ADVANCE(TMA_PACKET_LENGTH);

    return { pt_packet(TMA) };
}


static std::optional<pt_packet> parse_vmcs(void)
{
    if(!LEFT(VMCS_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, VMCS_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != VMCS_OPPCODE)
        return std::nullopt;

    ADVANCE(VMCS_PACKET_LENGTH);

    return { pt_packet(VMCS) };
}


static std::optional<pt_packet> parse_ovf(void)
{
    if(!LEFT(OVF_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, OVF_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != OVF_OPPCODE)
        return std::nullopt;

    ADVANCE(OVF_PACKET_LENGTH);

    return { pt_packet(OVF) };
}


static std::optional<pt_packet> parse_cyc(void)
{
    // Todo: implement this
    return std::nullopt;
}


static std::optional<pt_packet> parse_psb(void)
{
    if(!LEFT(PSB_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, PSB_PACKET_LENGTH);

    char expected_buffer[] = PSB_PACKET_FULL;

    if(memcmp(buffer, expected_buffer, PSB_PACKET_LENGTH) != 0)
        return std::nullopt;

    ADVANCE(PSB_PACKET_LENGTH);

    return { pt_packet(PSB) };
}


static std::optional<pt_packet> parse_psb_end(void)
{
    if(!LEFT(PSB_END_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, PSB_END_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != PSB_END_OPPCODE)
        return std::nullopt;

    ADVANCE(PSB_END_PACKET_LENGTH);

    return { pt_packet(PSBEND) };
}


static std::optional<pt_packet> parse_mnt(void)
{
    if(!LEFT(MNT_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, MNT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != MNT_OPPCODE_1 || 
       buffer[2] != MNT_OPPCODE_2)
        return std::nullopt;

    ADVANCE(MNT_PACKET_LENGTH);

    return { pt_packet(MNT) };
}


static std::optional<pt_packet> parse_pad(void)
{
    if(!LEFT(PAD_PACKET_LENGTH))   
        return std::nullopt;

    INIT_BUFFER(buffer, PAD_PACKET_LENGTH);

    if(buffer[0] != PAD_OPPCODE)
        return std::nullopt;

    ADVANCE(PAD_PACKET_LENGTH);

    return { pt_packet(PAD) };
}


static std::optional<pt_packet> parse_ptw(void) 
{
    if(!LEFT(PTW_HEADER_LENGTH))
        return std::nullopt;

    INIT_BUFFER(header, PTW_HEADER_LENGTH);

    if(header[0] != OPPCODE_STARTING_BYTE && 
       LOWER_BITS(header[1], 5) != PTW_OPPCODE)
        return std::nullopt;

    unsigned char payload_bits = MIDDLE_BITS(header[1], 7, 5);

    if(payload_bits != PTW_L1_CODE && payload_bits != PTW_L2_CODE)
        return std::nullopt;

    unsigned char packet_length = PTW_HEADER_LENGTH + 
        (payload_bits == PTW_L1_CODE) ? PTW_BODY_LENGTH_1 : PTW_BODY_LENGTH_2;

    ADVANCE(packet_length);

    return { pt_packet(PTW) };
}


static std::optional<pt_packet> parse_exstop(void)
{
    if(!LEFT(EXSTOP_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, EXSTOP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       LOWER_BITS(buffer[1], 7) != EXSTOP_OPPCODE)
        return std::nullopt;

    ADVANCE(EXSTOP_PACKET_LENGTH);

    return { pt_packet(EXSTOP) };
}


static std::optional<pt_packet> parse_mwait(void)
{
    if(!LEFT(MWAIT_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, MWAIT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != MWAIT_OPPCODE)
        return std::nullopt;

    ADVANCE(MWAIT_PACKET_LENGTH);

    return { pt_packet(MWAIT) };
}


static std::optional<pt_packet> parse_pwre(void)
{
    if(!LEFT(PWRE_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, PWRE_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PWRE_OPPCODE)
        return std::nullopt;

    ADVANCE(PWRE_PACKET_LENGTH);

    return { pt_packet(PWRE) };
}


static std::optional<pt_packet> parse_pwrx(void)
{
    if(!LEFT(PWRX_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, PWRX_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PWRX_OPPCODE)
        return std::nullopt;

    ADVANCE(PWRX_PACKET_LENGTH);

    return { pt_packet(PWRX) };
}


static std::optional<pt_packet> parse_bbp(void)
{
    if(!LEFT(BBP_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, BBP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != BBP_OPPCODE)
        return std::nullopt;

    ADVANCE(BBP_PACKET_LENGTH);

    return { pt_packet(BBP) };
}


static std::optional<pt_packet> parse_bip(void)
{
    // Todo implement
    return std::nullopt;
}


static std::optional<pt_packet> parse_bep(void)
{
    if(!LEFT(BEP_PACKET_LENGTH))
        return std::nullopt;

    INIT_BUFFER(buffer, BEP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       LOWER_BITS(buffer[1], 7) != BEP_OPPCODE)
        return std::nullopt;

    ADVANCE(BEP_PACKET_LENGTH);

    return { pt_packet(BEP) };
}


static std::optional<pt_packet> parse_cfe(void)
{
    if(!LEFT(CFE_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, CFE_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != CFE_OPPCODE)
        return std::nullopt;

    ADVANCE(CFE_PACKET_LENGTH);

    return { pt_packet(CFE) };
}


static std::optional<pt_packet> parse_evd(void)
{
    if(!LEFT(EVD_PACKET_LENGTH))
        return std::nullopt;
    
    INIT_BUFFER(buffer, EVD_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != EVD_OPPCODE)
        return std::nullopt;

    ADVANCE(EVD_PACKET_LENGTH);

    return { pt_packet(EVD) };
}


static pt_packet parse_unkown(void)
{
    u8 byte;
    GET_BYTES(&byte, 1);
    ADVANCE(1);

    return pt_packet(unkown_packet_data(byte));
}

/* ***** Debugging ***** */
static void print_packet(const pt_packet& packet)
{
    switch (packet.type) {
    case TNT:
        print_tnt(packet);
        break;
    case TIP:
        print_tip(packet);
        break;
    case TIP_OUT_OF_CONTEXT:
        printf("TIP - Out of Context\n");
        break;
    case PIP:
        printf("PIP\n");
        break;
    case MODE:
        printf("\n ----- MODE ----- \n\n");
        break;
    case TRACE_STOP:
        printf("TRACE_STOP\n");
        break;
    case CBR:
        printf("CBR\n");
        break;
    case TSC:
        printf("TSC\n");
        break;
    case MTC:
        printf("MTC\n");
        break;
    case TMA:
        printf("TMA\n");
        break;
    case VMCS:
        printf("VMCS\n");
        break;
    case OVF:
        printf("OVF\n");
        break;
    case CYC:
        printf("CYC\n");
        break;
    case PSB:
        printf("\n ----- ----- PSB ----- -----\n\n");
        break;
    case PSBEND:
        printf("\n ----- ----- END ----- ----- \n\n");
        break;
    case MNT:
        printf("MNT\n");
        break;
    case PAD:
        printf("PAD\n");
        break;
    case PTW:
        printf("PTW\n");
        break;
    case EXSTOP:
        printf("EXSTOP\n");
        break;
    case MWAIT:
        printf("MWAIT\n");
        break;
    case PWRE:
        printf("PWRE\n");
        break;
    case PWRX:
        printf("PWRX\n");
        break;
    case BBP:
        printf("BBP\n");
        break;
    case BIP:
        printf("BIP\n");
        break;
    case BEP:
        printf("BEP\n");
        break;
    case CFE:
        printf("CFE\n");
        break;
    case EVD:
        printf("EVD\n");
        break;
    case UNKOWN:
        printf("UNKOWN: " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(packet.unkown_data.byte));
        break;
    }
}


static void print_tip(const pt_packet& packet)
{
    // Print Type 
    printf("TIP ");

    switch(packet.tip_data.type) {
    case TIP_TIP: printf("-"); break;
    case TIP_PGE: printf("PGE -"); break;
    case TIP_PGD: printf("PGD -"); break;
    case TIP_FUP: printf("FUP -"); break;
    }

    printf(" %u - ", packet.tip_data.last_ip_use);

    // Print Ip
    printf("0x%lX\n", packet.tip_data.ip);
}


static void print_tnt(const pt_packet& packet)
{
    printf("TNT %u: ", packet.tnt_data.size);

    for(int i = 0; i < packet.tnt_data.size; i++) {
        printf("%u", packet.tnt_data.tnt[i]);
    }

    printf("\n");
}


/* ***** File Management ***** */
static void load_trace_file(char *file_name)
{
    trace_data = fopen(file_name, "rb");

    if(trace_data == NULL) {
        fprintf(stderr, "Failed to open data file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    fseek(trace_data, 0L, SEEK_END);
    size = ftell(trace_data);
    fseek(trace_data, 0L, SEEK_SET);

    offset = 0;
}


static void load_mapping_file(char *file_name) 
{
    FILE* mapping_data = fopen(file_name, "r");

    if(mapping_data == NULL) {
        fprintf(stderr, "Failed to open data file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    // Skip Header
    // Todo: implement

    // Read Data 
    unsigned long guest_pc;
    unsigned long host_pc;

    while(fscanf(mapping_data, "%lX, %lX\n", &guest_pc, &host_pc) != EOF) {
        host_ip_to_guest_ip[host_pc] = guest_pc;
    }

    fclose(mapping_data);
}


static unsigned long get_mapping(unsigned long host_pc) 
{
    return host_ip_to_guest_ip[host_pc];   
}


static void load_output_file(char *file_name)
{
    out_file = fopen(file_name, "w+");

    if(out_file == NULL) {
        fprintf(stderr, "Failed to open trace output file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }
}


static void log_basic_block(unsigned long id) 
{
    fprintf(out_file, "%lX\n", id);
}