#include "types.h"

#include "asm-parse.h"

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


static std::unordered_map<u64, u64> host_ip_to_guest_ip;
static bool use_asm;

// #define DEBUG_MODE_
#define DEBUG_TIME_

#ifdef DEBUG_MODE_ 
#define printf_debug(...); printf(__VA_ARGS__);
#else 
#define printf_debug(...);
#endif

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

#define BUFFER_SIZE 1073741824

static u8 _buffer[BUFFER_SIZE];
static u32 _pos_in_buffer = 0;

static void __advance(pt_state& state, u8 n);
static void __get_bytes(pt_state& state, u8 *buffer, u8 n);
static void __load_data_into_buffer(pt_state& state);

#define LEFT(n) ((state.size - state.offset) >= n)
#define ADVANCE(n) __advance(state, n)
#define GET_BYTES(buffer, size) __get_bytes(state, buffer, size)
#define INIT_BUFFER(name, size) \
    if(_pos_in_buffer + size > BUFFER_SIZE) {  \
        __load_data_into_buffer(state); \
    } \
    u8 *name = _buffer + _pos_in_buffer;

#define LOWER_BITS(value, n) (value & ((1 << n) - 1))
#define MIDDLE_BITS(value, uppwer, lower) (value & (((1 << uppwer) - 1) << lower))

#define RETURN_IF(x) \
    if(x(state, packet)) return packet
#define RETURN_IF_2(x, y) \
    if(x(state, packet, y)) return packet


void start(
    const char* asm_file, const char* pt_trace_file, 
    const char* mapping_file, const char* out_file, 
    bool _use_asm
){
    use_asm = _use_asm;
    
    load_mapping_file(mapping_file);

    pt_state state; 

    if(use_asm) { 
        asm_init(state.asm_parsing_state, asm_file);
    }

    load_output_file(state, out_file);
    load_trace_file(state, pt_trace_file);
    
    test(state);

    if(state.previous_guest_ip != 0) {
        // Record the lat basic block which may have 
        // not been saved yet
        log_basic_block(state, state.previous_guest_ip);
    }

    fclose(state.out_file);
}


void parse(pt_state& state) 
{
#ifdef DEBUG_MODE_
    printf(" -------- Intel PT Start ---------- \n\n");
    printf("Size: %lu\n", state.size);
#endif

    std::optional<pt_packet> maybe_packet;

    while((maybe_packet = try_get_next_packet(state))) {
        pt_packet packet = *maybe_packet;

        if(packet.type == PAD) {
            // No need to track PAD packets as they do not
            // provide any useful information 
            state.pad_count++; // Used for debugging 
            continue;
        }

        print_packet_debug(packet, state);

        if(packet.type == UNKOWN) {
            // No need to track unkown packets but still 
            // want to print for debugging purposes 
            continue;        
        }

        state.last_packet = &packet;

        // Handle this packet 
        if(packet.type == PSB) {
            state.in_psb = true;
        } else if(packet.type == PSBEND) {
            state.in_psb = false;
        } else if(packet.type == TIP) {
            handle_tip(state);
        } 

        // Follow asm if possible
        if(can_follow_asm(state)) {
            follow_asm(state);
        }

        // Keep track if the prev packet was mode / ovf
        state.last_was_mode = false;
        state.last_was_ovf = false;

        if(packet.type == MODE) {
            state.last_was_mode = true;
        } else if(packet.type == OVF) {
            state.last_was_ovf = true;
        }
    }
}


static inline void handle_tip(pt_state& state) 
{
    bool update_ip = true; 
    bool was_in_fup = false;

    tip_packet_data *tip_data = &state.last_packet->tip_data;

    state.last_tip_was_breakpoint = 
        tip_data->ip == state.breakpoint_ip;
        // If a call to the breakpoint has been made record this in 
        // the state so it can be used to continue to follow asm

    if(tip_data->type == TIP_TIP && state.breakpoint_ip == 0 &&
       state.next_tip_is_breakpoint) {
        // This is the first call to the breakpoint functoin. We can 
        // use this ip to record it for future use 
        state.breakpoint_ip = tip_data->ip;
        state.last_tip_was_breakpoint = true;

        printf_debug(
            "  Setting: breakpoint_ip: 0x%lX\n", state.breakpoint_ip
        );
    }


    if(tip_data->type == TIP_TIP && state.qemu_caller_ip == 0) {
        // This is the first TIP packet of the trace. We can use 
        // this ip as the qemu_call_ip, called after every ipt_start 
        state.qemu_caller_ip = tip_data->ip;
        
        printf_debug(
            "  Setting: qemu_caller_ip: 0x%lX\n", state.qemu_caller_ip
        );
    }
    

    if(tip_data->type == TIP_FUP &&
            !(state.last_was_mode || state.last_was_ovf)
        ) {
        // We have found an unbound FUP packet. Expecting to 
        // to see a pgd packet to bind to this one 
        state.in_fup = true;
    }

    if((tip_data->type == TIP_PGD || tip_data->type == TIP_PGE) && 
        state.in_fup) {
        // We have found an a PGD packet which binds to the 
        // previous FUP packet 
        state.in_fup = false;
        was_in_fup = true;
    }

    if((state.last_ip_was_reached_by_u_jump &&
       state.last_ip_had_mapping && (state.in_psb || state.in_fup)) || (
        was_in_fup && state.last_ip_had_mapping && 
        state.last_tip_ip == tip_data->ip && 
        state.last_tip_ip == state.current_ip
       )) {
        // Want to remove the last ip from the record has we will
        // reach it again. This may not be entierly true tbh 
        printf_debug("  NOTE: Removing previous block from save\n");
        state.previous_guest_ip = 0;
    }

    if(state.in_fup) { // Cannot update current ip
        printf_debug("  IN FUP\n");
        return;
    }

    if(state.current_ip == tip_data->ip && 
       state.last_tip_ip == state.current_ip && 
       tip_data->type == TIP_FUP && state.in_psb) {
        // We have resived a refresh of the current ip, but it 
        // is the same as the current. This will cuase a log to 
        // occour twice, we don't want that. 
        update_ip = false;
    }


    // Can update the current ip 
    if(update_ip) {
        state.last_tip_ip = tip_data->ip;
        update_current_ip(state, tip_data->ip);
    }


    if(tip_data->ip == state.qemu_caller_ip && 
       state.qemu_return_ip == 0 && use_asm) {
        // If we have just set the qemu_caller_ip, after updating the 
        // current ip the first basic block of asm will be parsed 
        // we can use this to get the qemu_return_ip, jumped to prior to 
        // leaving jit code. It is always the last jmp in a block 
        state.qemu_return_ip = get_last_jmp_loc(
            state.asm_parsing_state
        );

        printf_debug(
            "  Setting: qemu_return_ip: 0x%lX\n", state.qemu_return_ip
        );
    }

    // reset if needed 
    state.next_tip_is_breakpoint = false;
}


static inline bool can_follow_asm(pt_state& state)
{
    return 
        (
            (state.last_packet->type == TIP && !state.in_fup && 
             !state.last_tip_was_breakpoint /* want to wait for tnt */) || 
            (state.last_packet->type == TNT)
        ) && (
            !state.in_psb
        ) && use_asm;
}


static inline void follow_asm(pt_state& state)
{
    bool has_tnt = state.last_packet->type == TNT;

    u32 tnt_packet_p = 0;
    tnt_packet_data *tnt_packet = has_tnt ? 
        &state.last_packet->tnt_data : NULL;

    // Check if we have just exited a breakpoint
    if(state.last_tip_was_breakpoint) {
        if(!has_tnt) {
            printf("Error: cannot return from breakpoint without tnt\n");
            exit(EXIT_FAILURE);
        }

        if(!tnt_packet->tnt[tnt_packet_p++]) {
            printf("Error: return from breakpoint but tnt marked as not taken\n");
            exit(EXIT_FAILURE);
        }

        // can return from this breakpoint call
        state.last_tip_was_breakpoint = false;

        state.last_ip_was_reached_by_u_jump = false;

        update_current_ip(
            state, state.breakpoint_return_ip
        );
    }

    // Follow instructoins until either 
    //  1. A conditional jmp without a corisponding tnt is reached
    //  2. A call to qemu code is reached 
    //  3. A direct jmp takes execution back to the qemu code (occours at the end of translated blocks)

     if(!state.tracing_jit_code)
        return; // Not in jitted code, no asm to follow

    bool can_continue = true;

    while(can_continue && state.tracing_jit_code) {
        // Get the next instruction to follow 
        pt_instruction instr;

        auto parsed_instr = get_next_instr(
            state, state.current_ip, instr
        );

        if(!parsed_instr) {
            can_continue = false;
            break;
        }

        // Follow this instruction 
        switch(instr.type) {
        case PT_JMP: // Follow this jump 
            printf_debug(
                "  TU. 0x%lX jmp 0x%lX\n", instr.loc, instr.des
            );

            if(instr.des == state.qemu_return_ip) {
                printf_debug("    JMP. leaving jit code\n");
                // Leaving jit code, cannot continue to follow asm
                // this will be updated in the state by update_current_ip
            }

            update_current_ip(
                state, instr.des
            );

            // Set this to help us back track in the event
            // that a psb-fup-psbend event is sent inbetween 
            // an unconditional jump and the next real-packet 
            state.last_ip_was_reached_by_u_jump = true;
            
            break;
        case PT_JXX: // Follow this conditional jump
            if(!has_tnt || tnt_packet_p >= tnt_packet->size) {
                // Need more tnt packet data to continue 
                can_continue = false;
                break;
            }

            // If we do/don't take a conditional jump
            // that still updates the ip resetting the u_jump status
            state.last_ip_was_reached_by_u_jump = false;

            if(!tnt_packet->tnt[tnt_packet_p++]) {
                // Conditional jump is not taken
                state.current_ip = instr.loc + 1;

                printf_debug(
                    "  NT. 0x%lX jxx 0x%lX\n", instr.loc, instr.des
                );

                break;
            }

            // Conditional jump is taken
            printf_debug(
                "  TC. 0x%lX jxx 0x%lX\n", instr.loc, instr.des
            );

            if(instr.des == state.qemu_return_ip) {
                printf_debug("    JMP. leaving jit code\n");
                // Leaving jit code, cannot continue to follow asm
                // this will be updated in the state by update_current_ip
            }

            update_current_ip(
                state, instr.des
            );
            break;
        case PT_CALL: { // Handle this call
            // TODO: Need to move the first instance of the call to the first basic block

            // Cannot continue to follow calls 
            can_continue = false;

            u64 breakpoint_return_ip = instr.loc + 1;


            if(instr.is_breakpoint) {
                printf_debug(
                    "  TU. 0x%lX call breakpoint\n", instr.loc
                );
                
                state.next_tip_is_breakpoint = true;
            } else {
                printf_debug(
                    "  TU. 0x%lX call qemu\n", instr.loc
                );

                // return is not next instruction, but next again
                pt_instruction i;

                auto mi = get_next_instr(
                    state, breakpoint_return_ip, i
                );

                if(!mi) {
                    printf("    Error: qemu call is not followed by breakpoint\n");
                    exit(EXIT_FAILURE);
                }

                breakpoint_return_ip = i.loc + 1;
            }

            state.breakpoint_return_ip = breakpoint_return_ip;

            break;
        } }
    }
}  


static inline void update_current_ip(
    pt_state& state, u64 ip
) {
    state.current_ip = ip;

    state.last_ip_was_reached_by_u_jump = false; // reset 

    // Check if we can advance the asm
    if(state.current_ip == state.qemu_caller_ip && use_asm) {
        advance_to_ipt_start(state.asm_parsing_state);
    }

    // Check if this ip is jitted code 
    state.tracing_jit_code = ip_inside_block(
        state.asm_parsing_state, ip
    );

    // Check if this ip maps to a basic block
    u64 guest_ip = get_mapping(state.current_ip);

    state.last_ip_had_mapping = guest_ip != 0;

    if(guest_ip == 0) 
        return; // Doesn't map nothng more to do 
    // Does map log it and check for errors 
    
    log_basic_block(state, guest_ip);

    printf_debug(
        "    Host IP: 0x%lX -> Guest IP: 0x%lX\n", 
        state.current_ip, guest_ip
    );

    if(!state.tracing_jit_code && use_asm) {
        printf(
            "    Error: The block containing the above ip"
            " has not been translated: 0x%lx\n", guest_ip
        );
        exit(EXIT_FAILURE);
    }   
}



/* Instructions */

static inline bool get_next_instr(
    pt_state& state, u64 ip, pt_instruction& instruction
) {
    // Todo: Maybe add an option to check the next instruction
    //       is not outside of the current block 
    if(!state.tracing_jit_code) false;
    
    // Simple case jit instruction
    auto *instr = get_next_jit_instr(
        state.asm_parsing_state, ip
    );

    if(instr == NULL) false;

    instruction.is_qemu_src = false;
    instruction.type = jit_to_pt_instr_type(instr->type);
    instruction.loc = instr->loc;
    instruction.des = instr->des;
    instruction.is_breakpoint = instr->is_breakpoint;


    // return { pt_instruction(
    //     jit_to_pt_instr_type(instr->type), false,
    //     instr->loc, instr->des, instr->is_breakpoint
    // ) };

    return true;
}


static inline pt_instruction_type jit_to_pt_instr_type(
    jit_asm_type type
) {
    switch (type) {
    case JIT_JXX: return PT_JXX;
    case JIT_JMP: return PT_JMP;
    case JIT_CALL: return PT_CALL;
    }
}



static inline void print_packet_debug(pt_packet& packet, pt_state& state)
{
#ifdef DEBUG_MODE_
    if(state.pad_count > 0) {
        printf("PAD x %lu\n", state.pad_count);
        state.pad_count = 0;
    }

    print_packet(packet);
#endif
}

/* ***** Concurrent Parsing ***** */
static std::optional<pt_packet> try_get_next_packet(pt_state& state)
{
#ifdef DEBUG_TIME_
    static u8 last_percentage = -1;
#endif
    // Todo: need to move this out of the function into pt_state 
    static u64 last_tip_ip = 0;

#ifdef DEBUG_MODE_
    u64 old_offset = state.offset;
#endif

    if(state.offset >= state.size) {
        // No more packets
        return std::nullopt;
    }

#ifdef DEBUG_TIME_
    if((u8)(((double)state.offset / state.size) * 100) != last_percentage) {
        last_percentage = ((double)state.offset / state.size) * 100;
        fprintf(stderr, "TIME: %u%%\n", last_percentage);
        printf("TIME: %u%%\n", last_percentage);
    }
#endif

    pt_packet packet = get_next_packet(state, last_tip_ip);

#ifdef DEBUG_MODE_
    if(packet.type != PAD) printf("OFST: %u: ", old_offset);
#endif

    if(packet.type == TIP) {
        last_tip_ip = packet.tip_data.ip;
    }

    return { packet };
}


/* ***** Parsing ***** */
static inline pt_packet get_next_packet(pt_state& state, u64 curr_ip)
{
    pt_packet packet(UNKOWN); // Todo: rename unknown 
    
    RETURN_IF(parse_psb);
    RETURN_IF(parse_psb_end);
    RETURN_IF(parse_tnt);
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

    parse_unkown(state, packet);

    return packet;
}


static inline bool parse_tnt(pt_state& state, pt_packet& packet) 
{
    u32 current_size = 0;

    if(!parse_short_tnt(state, packet, current_size) && 
       !parse_long_tnt(state, packet, current_size)) {
        return false;
    }

    // Todo: if adding support for long tnt make the 7 47 or
    // can deal with parings lon tnt then short if still space
    while(current_size + 6 < TNT_PACKET_MAX_SIZE) {
        if(!parse_short_tnt(state, packet, current_size) && 
           !parse_long_tnt(state, packet, current_size)) {
            break;
        }
    }

    packet.tnt_data.size = current_size;

    if (current_size != 0) {
        return true;
    }
    
    return false;
}


static inline bool parse_short_tnt(pt_state& state, pt_packet& packet, u32& start_pos)
{
    // Attempt to pase a short TNT packet
    if(!LEFT(SHORT_TNT_PACKET_LENGTH))
        return false;
    
    u8 byte;
    GET_BYTES(&byte, 1);

    if(LOWER_BITS(byte, 1) != 0) 
        return false;

    int start_bit = 6;

    for(; start_bit > 0; start_bit--) {
        if(byte & (0b10 << start_bit)) {
            break;
        }
    }

    if(start_bit == 0) return false;

    // Is Short TNT packet. Parse it's data
    tnt_packet_data& data = packet.tnt_data;
    //data.size = start_bit;

    for(int i = start_bit - 1; i >= 0; i--) {
        bool taken = (byte & (0b10 << i));
        data.tnt[start_pos + start_bit - (i + 1)] = taken;
    }

    start_pos += start_bit;
    
    ADVANCE(1);

    packet.type = TNT;

    return true;
}

static inline bool parse_long_tnt(pt_state& state, pt_packet& packet, u32& start_pos)
{
     // Attempt to parse a Long TNT packet 
    if(!LEFT(LONG_TNT_PACKET_LENGTH)) 
        return false;

    INIT_BUFFER(buffer, LONG_TNT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != LONG_TNT_OPPCODE) 
        return false;

    printf("LONG TNT NOT IMPLEMENTED\n");
    exit(EXIT_FAILURE);

    ADVANCE(LONG_TNT_PACKET_LENGTH);

    // TODO: implement 
    return false;
}


static inline bool parse_tip(pt_state& state, pt_packet& packet, u64 curr_ip) 
{
    if(!LEFT(TIP_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, TIP_PACKET_LENGTH);

    // Get the type of this packet 
    auto type = parse_tip_type(buffer);

    if(!type) return false;

    // Check if the ip is within context
    u8 ip_bits = buffer[0] >> 5;

    if(ip_bits == 0b000) {
        ADVANCE(1);
        packet.type = TIP_OUT_OF_CONTEXT;
        return true;
    }

    // ip in context get compression status
    auto last_ip_use = parse_tip_ip_use(ip_bits);
    if(!last_ip_use) return false;

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

    // Finished return packet
    ADVANCE(TIP_PACKET_LENGTH - *last_ip_use);

    packet.tip_data = tip_packet_data(
        *type, ip_bits, *last_ip_use, ip_buffer, ip
    );
    packet.type = TIP;

    return true;
}  


static std::optional<pt_tip_type> parse_tip_type(u8 *buffer)
{
    u8 bits = LOWER_BITS(buffer[0], TIP_OPPCODE_LENGTH_BITS);

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


static inline bool parse_pip(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PIP_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, PIP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PIP_OPPCODE)
        return false;

    ADVANCE(PIP_PACKET_LENGTH);

    packet.type = PIP;

    return true;
}


static inline bool parse_mode(pt_state& state, pt_packet& packet)
{
    if(!LEFT(MODE_PACKET_LENGTH))    
        return false;
    
    INIT_BUFFER(buffer, MODE_PACKET_LENGTH);

    if(buffer[0] != MODE_OPPCODE)
        return false;

    // Todo: Parse the two different types of mode

    ADVANCE(MODE_PACKET_LENGTH);

    packet.type = MODE;

    return true;
}


static inline bool parse_trace_stop(pt_state& state, pt_packet& packet) 
{
    if(!LEFT(TRACE_STOP_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, TRACE_STOP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != TRACE_STOP_OPPCODE)
        return false;
    
    ADVANCE(TRACE_STOP_PACKET_LENGTH);

    packet.type = TRACE_STOP;

    return true;
}


static inline bool parse_cbr(pt_state& state, pt_packet& packet) 
{
    if(!LEFT(CBR_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, CBR_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != CBR_OPPCODE)
        return false;

    ADVANCE(CBR_PACKET_LENGTH);

    packet.type = CBR;

    return true;
}


static inline bool parse_tsc(pt_state& state, pt_packet& packet) 
{
    if(!LEFT(TSC_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, TSC_PACKET_LENGTH);

    if(buffer[0] != TSC_OPPCODE)
        return false;

    ADVANCE(TSC_PACKET_LENGTH);

    packet.type = TSC;

    return true;
}


static inline bool parse_mtc(pt_state& state, pt_packet& packet)
{
    if(!LEFT(MTC_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, MTC_PACKET_LENGTH);

    if(buffer[0] != MTC_OPPCODE)
        return false;

    ADVANCE(TSC_PACKET_LENGTH);

    packet.type = MTC;

    return true;
}


static inline bool parse_tma(pt_state& state, pt_packet& packet)
{
    if(!LEFT(TMA_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, TMA_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != TMA_OPPCODE) 
        return false;
    
    ADVANCE(TMA_PACKET_LENGTH);

    packet.type = TMA;

    return true;
}


static inline bool parse_vmcs(pt_state& state, pt_packet& packet)
{
    if(!LEFT(VMCS_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, VMCS_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != VMCS_OPPCODE)
        return false;

    ADVANCE(VMCS_PACKET_LENGTH);

    packet.type = VMCS;

    return true;
}


static inline bool parse_ovf(pt_state& state, pt_packet& packet)
{
    if(!LEFT(OVF_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, OVF_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != OVF_OPPCODE)
        return false;

    ADVANCE(OVF_PACKET_LENGTH);

    packet.type = OVF;

    return true;
}


static inline bool parse_cyc(pt_state& state, pt_packet& packet)
{
    // Todo: implement this
    return false;
}


static inline bool parse_psb(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PSB_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, PSB_PACKET_LENGTH);

    char expected_buffer[] = PSB_PACKET_FULL;

    if(memcmp(buffer, expected_buffer, PSB_PACKET_LENGTH) != 0)
        return false;

    ADVANCE(PSB_PACKET_LENGTH);

    packet.type = PSB;

    return true;
}


static inline bool parse_psb_end(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PSB_END_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, PSB_END_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != PSB_END_OPPCODE)
        return false;

    ADVANCE(PSB_END_PACKET_LENGTH);

    packet.type = PSBEND;

    return true;
}


static inline bool parse_mnt(pt_state& state, pt_packet& packet)
{
    if(!LEFT(MNT_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, MNT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE || 
       buffer[1] != MNT_OPPCODE_1 || 
       buffer[2] != MNT_OPPCODE_2)
        return false;

    ADVANCE(MNT_PACKET_LENGTH);

    packet.type = MNT;

    return true;
}


static inline bool parse_pad(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PAD_PACKET_LENGTH))   
        return false;

    INIT_BUFFER(buffer, PAD_PACKET_LENGTH);

    if(buffer[0] != PAD_OPPCODE)
        return false;

    ADVANCE(PAD_PACKET_LENGTH);

    packet.type = PAD;

    return true;
}


static inline bool parse_ptw(pt_state& state, pt_packet& packet) 
{
    if(!LEFT(PTW_HEADER_LENGTH))
        return false;

    INIT_BUFFER(header, PTW_HEADER_LENGTH);

    if(header[0] != OPPCODE_STARTING_BYTE && 
       LOWER_BITS(header[1], 5) != PTW_OPPCODE)
        return false;

    u8 payload_bits = MIDDLE_BITS(header[1], 7, 5);

    if(payload_bits != PTW_L1_CODE && payload_bits != PTW_L2_CODE)
        return false;

    u8 packet_length = PTW_HEADER_LENGTH + 
        (payload_bits == PTW_L1_CODE) ? PTW_BODY_LENGTH_1 : PTW_BODY_LENGTH_2;

    ADVANCE(packet_length);

    packet.type = PTW;

    return true;
}


static inline bool parse_exstop(pt_state& state, pt_packet& packet)
{
    if(!LEFT(EXSTOP_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, EXSTOP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       LOWER_BITS(buffer[1], 7) != EXSTOP_OPPCODE)
        return false;

    ADVANCE(EXSTOP_PACKET_LENGTH);

    packet.type = EXSTOP;

    return true;
}


static inline bool parse_mwait(pt_state& state, pt_packet& packet)
{
    if(!LEFT(MWAIT_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, MWAIT_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != MWAIT_OPPCODE)
        return false;

    ADVANCE(MWAIT_PACKET_LENGTH);

    packet.type = MWAIT;

    return true;
}


static inline bool parse_pwre(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PWRE_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, PWRE_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PWRE_OPPCODE)
        return false;

    packet.type = PWRE;

    return true;
}


static inline bool parse_pwrx(pt_state& state, pt_packet& packet)
{
    if(!LEFT(PWRX_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, PWRX_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != PWRX_OPPCODE)
        return false;

    ADVANCE(PWRX_PACKET_LENGTH);

    packet.type = PWRX;

    return true;
}


static inline bool parse_bbp(pt_state& state, pt_packet& packet)
{
    if(!LEFT(BBP_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, BBP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != BBP_OPPCODE)
        return false;

    ADVANCE(BBP_PACKET_LENGTH);

    packet.type = BBP;

    return true;
}


static inline bool parse_bip(pt_state& state, pt_packet& packet)
{
    // Todo implement
    return false;
}


static inline bool parse_bep(pt_state& state, pt_packet& packet)
{
    if(!LEFT(BEP_PACKET_LENGTH))
        return false;

    INIT_BUFFER(buffer, BEP_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       LOWER_BITS(buffer[1], 7) != BEP_OPPCODE)
        return false;

    ADVANCE(BEP_PACKET_LENGTH);

    packet.type = BEP;

    return true;
}


static inline bool parse_cfe(pt_state& state, pt_packet& packet)
{
    if(!LEFT(CFE_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, CFE_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != CFE_OPPCODE)
        return false;

    ADVANCE(CFE_PACKET_LENGTH);

    packet.type = CFE;

    return true;
}


static inline bool parse_evd(pt_state& state, pt_packet& packet)
{
    if(!LEFT(EVD_PACKET_LENGTH))
        return false;
    
    INIT_BUFFER(buffer, EVD_PACKET_LENGTH);

    if(buffer[0] != OPPCODE_STARTING_BYTE ||
       buffer[1] != EVD_OPPCODE)
        return false;

    ADVANCE(EVD_PACKET_LENGTH);

    packet.type = EVD;    

    return  true;
}


static inline void parse_unkown(pt_state& state, pt_packet& packet)
{
    u8 byte;
    GET_BYTES(&byte, 1);
    ADVANCE(1);

    packet.type = UNKOWN;
    packet.unkown_data = unkown_packet_data(byte);
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
        printf("MODE\n");
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
        printf(
            "UNKOWN: " BYTE_TO_BINARY_PATTERN "\n", 
            BYTE_TO_BINARY(packet.unkown_data.byte)
        );
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
static void load_trace_file(pt_state& state, const char *file_name)
{
    state.trace_data = fopen(file_name, "rb");

    if(state.trace_data == NULL) {
        fprintf(stderr, "Failed to open data file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    // Get length of the file 
    fseek(state.trace_data, 0L, SEEK_END);
    state.size = ftell(state.trace_data);
    fseek(state.trace_data, 0L, SEEK_SET);

    state.offset = 0;

    __load_data_into_buffer(state);
}


static void __advance(pt_state& state, u8 n)
{
    state.offset += n; // Track global pos 
    _pos_in_buffer += n; // Track local pos 

    if(_pos_in_buffer < BUFFER_SIZE) return;

    __load_data_into_buffer(state);
}


static void __get_bytes(pt_state& state, u8 *buffer, u8 n)
{
    if(_pos_in_buffer + n >= BUFFER_SIZE) {  
        __load_data_into_buffer(state);
    }

    memcpy(buffer, _buffer + _pos_in_buffer, n);
}


static void __load_data_into_buffer(pt_state& state)
{
    size_t old_data = (_pos_in_buffer == 0) ? 
        0 : BUFFER_SIZE - _pos_in_buffer; 

    if(old_data > 0) {
        memcpy(
            _buffer, _buffer + _pos_in_buffer, old_data
        );
    }

    size_t new_data = BUFFER_SIZE - old_data;

    fread(_buffer + old_data, new_data, 1, state.trace_data);

    _pos_in_buffer = 0; // Reset local position
}


static void load_mapping_file(const char *file_name) 
{
    FILE* mapping_data = fopen(file_name, "r");

    if(mapping_data == NULL) {
        fprintf(stderr, "Failed to open data file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    // Read Data 
    unsigned long guest_pc;
    unsigned long host_pc;

    while(fscanf(mapping_data, "%lX, %lX\n", &guest_pc, &host_pc) != EOF) {
        host_ip_to_guest_ip[host_pc] = guest_pc;
    }

    fclose(mapping_data);
}


static u64 get_mapping(u64 host_pc) 
{
    return host_ip_to_guest_ip[host_pc];   
}


static void load_output_file(pt_state& state, const char *file_name)
{
    state.out_file = fopen(file_name, "w+");

    if(state.out_file == NULL) {
        fprintf(stderr, "Failed to open trace output file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }
}


static void log_basic_block(pt_state& state, u64 id) 
{
    if(state.previous_guest_ip != 0) {
        fprintf(state.out_file, "%lX\n", state.previous_guest_ip);
    } 
    state.previous_guest_ip = id;
}
