#include "asm-parse-internal.h"
#include "asm-parse.h"
#include "asm-types.h"

#include "mapping-parse.h"

#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

#include <chrono>

// #define ASM_PARSE_DEBUG_

static u64 start_count = 0;

void asm_init(asm_state& state, const char* asm_file_name) 
{
    state.asm_file = std::ifstream(asm_file_name);
}

#define PARSE_ELEMENT(x, y, z) \
    if(parse_ ## x(y, z)) return true

/* ***** JMP Management ***** */
inline bool update_last_seen_block(asm_state& state, u64 current_ip);

jit_asm_instruction* get_next_jit_instr(asm_state& state, u64 current_ip)
{
    // Search for the block contianing the instruction
    if(!update_last_seen_block(state, current_ip)) return NULL;

    // Search for the instruction in this block 
    auto instr_iter = state.last_seen_block
        ->instructions.lower_bound(current_ip);

    if(instr_iter == state.last_seen_block->instructions.end()) {
        printf(
            "Errror: Failed to find next instruction for: 0x%lX\n", current_ip
        ); 
        fprintf(stderr, 
            "Errror: Failed to find next instruction for: 0x%lX\n", current_ip
        ); 
        return NULL;
    }

    return instr_iter->second;
}

inline bool update_last_seen_block(asm_state& state, u64 current_ip) {
    if(state.last_seen_block != NULL && (
        current_ip >= state.last_seen_block->start_ip && 
        current_ip <= state.last_seen_block->end_ip
    )) {
        // Ip is in the current block do nothing
        return true;
    }

    // Ip is not in the current block update it 
    auto block_iter = state.ordered_blocks.upper_bound(current_ip);

    if(block_iter == state.ordered_blocks.begin() || (
        current_ip > (--block_iter)->second->end_ip
    )) {
        // No block can be found for this ip address
        fprintf(stderr, 
            "Error: Failed to find block for: 0x%lX\n", current_ip
        ); 
        printf(
            "Error: Failed to find block for: 0x%lX\n", current_ip
        ); 
        return false;
    }

    state.last_seen_block = block_iter->second;

    return true;
}


bool ip_inside_block(asm_state& state, u64 ip) 
{
    if(state.last_seen_block != NULL && (
        ip >= state.last_seen_block->start_ip && 
        ip <= state.last_seen_block->end_ip
    )) {
        // Ip is in the current block do nothing
        return true;
    }
    
    auto block_iter = state.ordered_blocks.upper_bound(ip);

    if(block_iter == state.ordered_blocks.begin() || (
        ip > (--block_iter)->second->end_ip
    )) {
        // Ip is not within a block
        return false;
    }

    state.last_seen_block = block_iter->second;

    return true;
}


/* ***** Parsing ***** */
static inline void save_instruction(
    asm_state& global_state, advance_state& state, jit_asm_instruction *instr
) {
    if(state.current_block == NULL) {
        std::cerr << "Error: Cannot save instruction to NULL block" << std::endl;       
        exit(EXIT_FAILURE);
    }

    state.current_block->instructions.emplace(instr->ip, instr);
    global_state.ordered_instructions.emplace(instr->ip, instr);
    global_state.unordered_instructions.emplace(instr->ip, instr);
}


void advance_to_ipt_start(asm_state& state)
{
    static int calls = 0; calls++;

    advance_state local_state;
    std::string line;

    while(getline(state.asm_file, line)) {
        // Parce the next trace element
        if(!parse_trace_element(line, local_state.current_element)) {
            std::cout << "Error Unkown asm String: " << line << std::endl;
            exit(EXIT_FAILURE);
        }

#ifdef ASM_PARSE_DEBUG_
        print_trace_element(local_state.current_element);
#endif

        // Handle the parsed trace element
        switch (local_state.current_element.type) {
        case BLOCK: 
            handle_block(state, local_state);
            break;
        case BLOCK_SIZE: 
            handle_block_size(state, local_state);
            break;
        case JMP: 
            handle_jmp(state, local_state);
            break;
        case COMPUTED_JMP:
            handle_computed_jmp(state, local_state);
            break;
        case JXX: 
            handle_jxx(state, local_state);
            break;
        case JXX_LDST: 
            handle_jxx_ldst(state, local_state);
            break;
        case CALL: 
            handle_call(state, local_state);
            break;
        case UPDATE: 
            handle_update(state, local_state);
            break;
        case LABEL:
            handle_label(state, local_state);
            break;
        case IPT_STOP:
            handle_ipt_stop(state, local_state);
            break;
        case IPT_START: // Finished parsing
            handle_ipt_start(state, local_state);
            return;
        }
    }

    std::cout << "Reached end of file, advanced to far: " << calls << std::endl;
    exit(EXIT_FAILURE);
}


/* ******** Buliding Data ******** */

static inline void handle_block(
    asm_state& global_state, advance_state& state
) {
    // Store the block start
    if(state.current_block != NULL) {
        printf("    Error cannot start a new block until previous saved\n");
        exit(EXIT_FAILURE);
    }

    state.current_block = new translated_block();

    state.current_block->start_ip = 
        state.current_element.block_ip;

    state.current_block->guest_ip = 
        get_mapping(state.current_element.block_ip);
    
    //  todo: maybe want to check if there if there are unset jumps 
}


static inline void handle_block_size(
    asm_state& global_state, advance_state& state
) {
    // Record block size
    if(state.current_block == NULL) {
        printf("    Error found block size without a block to map too\n");
        exit(EXIT_FAILURE);
    }

    // Update current block with final size and save 
    state.current_block->size = 
        state.current_element.block_size;

    state.current_block->end_ip = 
        state.current_block->start_ip + state.current_element.block_size;

    // Add all instructions to this block 
    auto instr_iter = state.current_block->instructions.rbegin();

    if (global_state.qemu_return_ip == 0) {
        // Check if need to set qemu_return_ip
        if (instr_iter->second->type != JIT_JMP) {
            printf("Error last instruction of a block should always be jmp\n");
            exit(EXIT_FAILURE);
        }

        global_state.qemu_return_ip = instr_iter->second->des.ip;
    }


    for(; instr_iter != state.current_block->instructions.rend(); ++instr_iter) {
        auto *instr = instr_iter->second;

        switch (instr->type) {
        case JIT_JMP:
            set_jump_destination(global_state, state, instr->des);
            break;
        case JIT_JXX: 
            set_jump_destination(global_state, state, instr->taken_des);
            set_jump_destination(global_state, state, instr->not_taken_des);
            break;
        case JIT_CALL:
            set_jump_destination(global_state, state, instr->return_des);
            break;
        }
    }   

    // Store this block in global state
    global_state.unordered_blocks[state.current_block->start_ip] = 
        state.current_block;
    global_state.ordered_blocks[state.current_block->start_ip] =
        state.current_block;
    
    state.current_block = NULL;
}


static inline void handle_update(
    asm_state& global_state, advance_state& state
) {
    // Update the given jump instruction
    auto instr_loc = state.current_element.loc;
    auto new_des = state.current_element.new_des;

    auto instr_iter = global_state.unordered_instructions.find(
        instr_loc
    );

    if(instr_iter == global_state.unordered_instructions.end()) {
        printf(
            "Failed to find instruction to update: %lX", instr_loc
        );
        exit(EXIT_FAILURE);
    }

    auto *instr = instr_iter->second;

    state.current_block = instr->block;
    
    switch (instr->type) {
    case JIT_JMP:
        update_jump_desitation(
            global_state, state, instr->des, new_des
        );
        break;
    case JIT_JXX: 
        update_jump_desitation(
            global_state, state, instr->taken_des, new_des
        );
        break;
    case JIT_CALL:
        printf("Error: Cannot update the location of a call\n");
        exit(EXIT_FAILURE);
        break;
    }

    state.current_block = NULL;
}


static inline void update_jump_desitation(
    asm_state& global_state, advance_state& state, 
    jmp_destination& destination, u64 new_destination
) {
    if(destination.type == COMPUTED) {
        printf("Warning udpating comptued jump unsure if okay\n");
    }

    destination.ip = new_destination;
    set_jump_destination(global_state, state, destination);
}


static inline void set_jump_destination(
    asm_state& global_state, advance_state& state, jmp_destination& destination
) {
    //If computed can't get destination
    if(destination.ip == 0) {
        destination.type = COMPUTED;
        return;
    }

    // Set the type of this destination
    if(destination.ip == global_state.qemu_return_ip || 
       destination.ip == global_state.qemu_return_ip - 2) {
        // Jump out of jitted code and back to qemu 
        destination.type = RETURN_TO_QEMU;
        return;
    }

    if(!(
        destination.ip >= state.current_block->start_ip && 
        destination.ip <= state.current_block->end_ip)
    ){
        // Jump to a new block 
        auto block = global_state.unordered_blocks.find(destination.ip);

        if (block == global_state.unordered_blocks.end()) {
            printf(
                "Error jump to block which does not exist: %lX\n",
                destination.ip
            );
            exit(EXIT_FAILURE);
        }

        destination.type = NEW_BLOCK;
        destination.next_block = block->second;
        destination.next_instr = block->second->instructions.begin()->second;
        return;
    }

    if (destination.ip == state.current_block->start_ip) {
        // Jump to the start of this block
        destination.type = NEW_BLOCK;
        destination.next_block = state.current_block;
        destination.next_instr = state.current_block->instructions.begin()->second;
        return;
    }

    // Jump within this block, get the next instructoin after jump location
    auto *next_instr = get_next_jump_within_block_after_ip(
        state.current_block, destination.ip
    );

    destination.type = SAME_BLOCK;
    destination.next_instr = next_instr;
    destination.next_block = NULL;
}


static inline jit_asm_instruction* get_next_jump_within_block_after_ip(
    translated_block* block, u64 start_ip
) {
    auto instr = block->instructions.lower_bound(start_ip);

    if(instr == block->instructions.end()) {
        printf(
            "Errror: Failed to find next instruction "
            "when translating: 0x%lX\n", start_ip
        ); 
        exit(EXIT_FAILURE);
    }

    return instr->second;
}


static inline void handle_jmp(
    asm_state& global_state, advance_state& state
) {
    // Store jmp
    auto *instr = new jit_asm_instruction();

    instr->type = JIT_JMP;
    instr->ip = state.current_element.loc;
    instr->des.ip = state.current_element.des;
    instr->block = state.current_block;

    save_instruction(global_state, state, instr);
}


static inline void handle_computed_jmp(
    asm_state& global_state, advance_state& state
) {
    auto *instr = new jit_asm_instruction();

    instr->type = JIT_JMP;
    instr->ip = state.current_element.loc;
    instr->des.type = COMPUTED;
    instr->des.ip = 0;
    instr->block = state.current_block;

    save_instruction(global_state, state, instr);
}


static inline void handle_jxx(
    asm_state& global_state, advance_state& state
) {
    // Store this JXX until a label is found
    if(state.unset_jxx.find(state.current_element.id) != state.unset_jxx.end()) {
        printf(
            "Error label already in use for jxx: %lX -> %u\n",
            state.current_element.loc, state.current_element.id
        );
        exit(EXIT_FAILURE);
    }

    state.unset_jxx[state.current_element.id] = state.current_element; 
}


static inline void handle_jxx_ldst(
    asm_state& global_state, advance_state& state
) {
    // Store jxx
    auto *instr = new jit_asm_instruction();

    instr->type = JIT_JXX;
    instr->ip = state.current_element.loc;
    instr->taken_des.ip = state.current_element.des;
    instr->not_taken_des.ip = state.current_element.loc + 1;
    instr->block = state.current_block;

    save_instruction(global_state, state, instr);
}


static inline void handle_call(
    asm_state& global_state, advance_state& state
) {
    // Store call
    auto *instr = new jit_asm_instruction();

    instr->type = JIT_CALL;
    instr->ip = state.current_element.loc;
    instr->is_breakpoint = state.current_element.is_breakpoint;
    instr->return_des.ip = state.current_element.loc + 1;
    instr->block = state.current_block;

    save_instruction(global_state, state, instr);
}


static inline void handle_label(
    asm_state& global_state, advance_state& state
) {
    // Use this label to update any jxx insutrctions
    if(state.unset_jxx.find(state.current_element.id) == state.unset_jxx.end()) {
        printf(
            "Error label does not have corrisponding jmp: %u -> %lX\n",
            state.current_element.id, state.current_element.loc
        );
        exit(EXIT_FAILURE);
    }

    trace_element jxx = state.unset_jxx[state.current_element.id];

    auto *instr = new jit_asm_instruction();

    instr->type = JIT_JXX;
    instr->ip = jxx.loc;
    instr->taken_des.ip = state.current_element.loc;
    instr->not_taken_des.ip = jxx.loc + 1;
    instr->block = state.current_block;

    save_instruction(global_state, state, instr);

    state.unset_jxx.erase(state.current_element.id);
}


static inline void handle_ipt_stop(
    asm_state& global_state, advance_state& state
) {
    // Noting to do 
}


static inline void handle_ipt_start(
    asm_state& global_state, advance_state& state
) {
    if(state.unset_jxx.size() == 0) 
        return;
    
    printf(
        "Reach ipt_start and there is still unset jxx instructions\n"
    );

    for(auto& i : state.unset_jxx) {
        printf(" - %lX\n", i.second.loc);
    }

    exit(EXIT_FAILURE);
}


/* ******** Debuggin ********* */

static inline void print_trace_element(trace_element& elmnt){
    switch(elmnt.type) {
    case BLOCK:
        printf("\nBLOCK: 0x%lX\n", elmnt.block_ip);
        break;
    case BLOCK_SIZE:
        printf("BLOCK_SIZE: %lu\n", elmnt.block_size);
        break;
    case JMP:
        printf("  JMP: 0x%lX -> 0x%lX\n", elmnt.loc, elmnt.des);
        break;
    case COMPUTED_JMP:
        printf("  JMP: 0x%lX -> ?\n", elmnt.loc);
        break;
    case JXX:
        printf("  JXX: 0x%lX -> %u\n", elmnt.loc, elmnt.id);
        break;
    case JXX_LDST:
        printf("  JXX_LDST: 0x%lX -> 0x%lX\n", elmnt.loc, elmnt.des);
        break;
    case UPDATE:
        printf("  UPDATE: 0x%lX -> 0x%lX\n", elmnt.loc, elmnt.new_des);
        break;
    case LABEL:
        printf("  LBL: %u -> 0x%lX\n", elmnt.id, elmnt.loc);
        break;
    case CALL:
        std::cout 
            << "  CALL: 0x" << std::uppercase << std::hex << elmnt.loc
            << " -> " << (elmnt.is_breakpoint ? "BreakPoint" : "QEMU")
            << std::endl;
        break;
    case IPT_START:
        printf("IPT_START: %lu\n\n", start_count++);
        break;
    case IPT_STOP:
        break;
    }
}


/* ******* Parsing *******  */

static inline bool parse_trace_element(std::string& l, trace_element& o) 
{
    PARSE_ELEMENT(block, l, o);
    PARSE_ELEMENT(block_size, l, o);
    PARSE_ELEMENT(jmp, l, o);
    PARSE_ELEMENT(jxx1, l, o);
    PARSE_ELEMENT(jxx2, l, o);
    PARSE_ELEMENT(update, l, o);
    PARSE_ELEMENT(label, l, o);
    PARSE_ELEMENT(ipt_start, l, o);
    PARSE_ELEMENT(ipt_stop, l, o);
    PARSE_ELEMENT(jxx_ldst, l, o);
    PARSE_ELEMENT(call, l, o);

    return false;
}


static inline bool parse_block(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("BLOCK: 0x")) return false;
    // BLOCK: 0x...
    u32 start_pos = 9;

    out.type = BLOCK;
    out.block_ip = parse_ip(line, start_pos); 

    return true;
}


static inline bool parse_jmp(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("JMP")) return false;
    // JMPX: 0x... 0x...

    u32 pos = 8;

    out.loc = parse_ip(line, pos);

    if(line[3] == '3') {
        // Computed jump e.g. JMPX: 0x.... eax
        out.type = COMPUTED_JMP;
        return true;
    }

    if(!(line[3] == '1' || line[3] == '2')) {
        cout << "Unsaported jmp found: " << line << endl;
        exit(EXIT_FAILURE);
    }

    // Regular jump

    pos += 2;

    out.type = JMP;
    out.des = parse_ip(line, pos);

    return true;
}


static inline bool parse_jxx1(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX1: 0x")) return false;
    // JXX: 0x... .

    u32 pos = 8;
    
    out.type = JXX;
    out.loc = parse_ip(line, pos); 
    out.id = parse_id(line, pos); 

    return true;
}



static inline bool parse_jxx2(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX2: 0x")) return false;
    // JXX: 0x... 0x...

    u32 pos = 8;
    
    out.type = JXX_LDST;
    out.loc = parse_ip(line, pos); 
    
    pos += 2;

    out.des = parse_ip(line, pos);

    return true;
}


static inline bool parse_jxx_ldst(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX_LDST: 0x")) return false;
    // JXX_LDST: 0x... 0x...

    u32 pos = 12;
    
    out.type = JXX_LDST;
    out.loc = parse_ip(line, pos);

    pos += 2;

    out.des = parse_ip(line, pos);

    return true;
}


static inline bool parse_update(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("UPDATE: 0x")) return false;
    // UPDATE: 0x... 0x...

    u32 pos = 10;

    out.type = UPDATE;
    out.loc = parse_ip(line, pos); 

    pos += 2;

    out.new_des = parse_ip(line, pos);

    return true;
}

static inline bool parse_label(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("LBL: ")) return false;
    // LBL: . 0x...

    u32 pos = 5;

    out.type = LABEL;
    out.id = parse_id(line, pos); 
    out.loc = parse_ip(line, pos);

    return true;
}


static inline bool parse_call(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("CALL: 0x")) return false;
    // CALL: 0x... .str.
    u32 pos = 8;

    out.type = CALL;
    out.loc = parse_ip(line, pos); 

    string func_string = line.substr(pos);

    out.qemu_des = 0; // get_call_loc(func_string);
    out.is_breakpoint = func_string.compare("ctrace_ipt_breakpoint") == 0;

    return true;
}


static inline bool parse_ipt_start(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("IPT_START:")) return false;
    out.type = IPT_START;
    return true;
}


static inline bool parse_ipt_stop(std::string& line, trace_element& out)
{
    if(!line.starts_with("IPT_STOP:")) return false;
    out.type = IPT_STOP;
    return true;
}


static inline bool parse_block_size(std::string& line, trace_element& out)
{
    if(!line.starts_with("BLOCK_SIZE: ")) return false;
    u32 pos = 12;

    out.type = BLOCK_SIZE;
    out.block_size = parse_id(line, pos);

    return true;
}


static u64 parse_ip(std::string& line, u32& pos)
{
    u64 output = 0;
    size_t size = line.size();

    while(pos < size) {
        u8 byte = line[pos++];

        if(byte >= '0' && byte <='9') byte -= '0';
        else if(byte >= 'a' && byte <='f') byte -= 'a' - 10;
        else if(byte >= 'A' && byte <= 'F') byte -='A' - 10;
        else break;

        output = (output << 4) | (byte & 0xF);
    }

    return output;
}


static u64 parse_id(std::string& line, u32& pos)
{
    u64 output = 0;
    size_t size = line.size();

    while(pos < size) {
        u8 byte = line[pos++];

        if(byte >= '0' && byte <= '9') byte -= '0';
        else break;

        output = (output * 10) + byte;
    }

    return output;
}

