#include "asm-parse-internal.h"
#include "asm-parse.h"
#include "asm-types.h"
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

jit_asm_instruction* get_next_jit_instr(asm_state& state, u64 current_ip)
{
    static basic_block *current_block = NULL;
    if(current_block == NULL || 
       current_ip < current_block->start_ip || 
       current_ip > current_block->end_ip){
        auto block = state.blocks.upper_bound(current_ip);

        if(block == state.blocks.begin() || 
          (current_ip > (--block)->second->end_ip)) {
            fprintf(
                stderr, "Error: Failed to find block for: 0x%lX\n", current_ip
            ); 
            printf(
                "Error: Failed to find block for: 0x%lX\n", current_ip
            ); 
            // exit(EXIT_FAILURE);    
            return NULL;
        }

        current_block = block->second;
    }

    auto instr = current_block->instructions.lower_bound(current_ip);

    if(instr == current_block->instructions.end()) {
        printf(
            "Errror: Failed to find next instruction for: 0x%lX\n", current_ip
        ); 
        fprintf(
                stderr, "Errror: Failed to find next instruction for: 0x%lX\n", current_ip
        ); 
        //exit(EXIT_FAILURE);
        return NULL;
    }

    return instr->second;
}


u64 get_last_jmp_loc(asm_state& state) 
{
    return (--state.instructions.end())->second->des;
}


bool ip_inside_block(asm_state& state, u64 ip) 
{
    using namespace std;
    auto block = state.blocks.find(ip);

    if(block != state.blocks.end()) { 
#ifdef ASM_PARSE_DEBUG_
        printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, block->first);
#endif
        return true;
    }

    auto block_ = state.blocks.upper_bound(ip);

    if(block_ == state.blocks.begin()) {
        return false;
    }
    block_--;

    if(!(ip < (block_->second->end_ip))) {
        return false;
    }

#ifdef ASM_PARSE_DEBUG_
    printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, block_->first);
#endif

    return true;
}


/* ***** Parsing ***** */
static inline void save_instruction(
    asm_state& state, jit_asm_instruction *instr, basic_block* bb
) {
    if(bb == NULL) {
        std::cerr << "Error: Cannot save instruction to NULL block" << std::endl;       
    }

    state.instructions.emplace(instr->loc, instr);
    bb->instructions.emplace(instr->loc, instr);    
}

void advance_to_ipt_start(asm_state& state)
{
    using namespace std;
    static int calls = 0;
    calls++;

    /* Track jumps waiting for a label*/
    unordered_map<int, trace_element> unset_jxx; 

    /* Track the current basic block */
    basic_block *current_block = NULL;

    string line;

    while(getline(state.asm_file, line)) {
        trace_element curr;

        // Parce the next trace element
        if(!parse_trace_element(line, curr)) {
            cout << "Error Unkownn String: " << line << endl;
            exit(EXIT_FAILURE);
        }

#ifdef ASM_PARSE_DEBUG_
        print_trace_element(curr);
#endif

        // Handle the parsed trace element
        switch (curr.type) {
        case BLOCK: // Store the block start
            if(current_block != NULL) {
                printf("    Error cannot start a new block until previous saved\n");
                exit(EXIT_FAILURE);
            }

            current_block = new basic_block();
            current_block->start_ip = curr.block_ip;
            //  todo: maybe want to check if there if there are unset jumps 
            break;
        case BLOCK_SIZE: // Record block size
            if(current_block == NULL) {
                printf("    Error found block size without a block to map too\n");
                exit(EXIT_FAILURE);
            }

            current_block->size = curr.block_size;
            current_block->end_ip = current_block->start_ip + curr.block_size;

            state.blocks[current_block->start_ip] = current_block;
            
            current_block = NULL;
            break;
        case JMP: // Store jmp
            save_instruction(state, new jit_asm_instruction(
                JIT_JMP, curr.loc, curr.des
            ), current_block);
            break;
        case JXX: // Store this JXX until a label is found
            if(unset_jxx.find(curr.id) != unset_jxx.end()) {
                cout << "Error label already in use for jxx: " << line << endl;
                exit(EXIT_FAILURE);
            }

            unset_jxx[curr.id] = curr; 
            break;
        case JXX_LDST: // Store jmp
            save_instruction(state, new jit_asm_instruction(
                JIT_JXX, curr.loc, curr.des
            ), current_block);
            break;
        case CALL: // Store call
            save_instruction(state, new jit_asm_instruction(
                JIT_CALL, curr.loc, curr.is_breakpoint
            ), current_block);
            break;
        case UPDATE: // Update jmp
            state.instructions[curr.loc]->des = curr.new_des;
            break;
        case LABEL: {// Use this label to update any jxx insutrctions
            if(unset_jxx.find(curr.id) == unset_jxx.end()) {
                cout 
                    << "Error label does not have corrisponding jmp: " 
                    << line << endl;
                exit(EXIT_FAILURE);
            }

            trace_element jxx = unset_jxx[curr.id];
            
            save_instruction(state, new jit_asm_instruction(
                JIT_JXX, jxx.loc, curr.loc
            ), current_block);

            unset_jxx.erase(curr.id);
            break;
        } case IPT_STOP:
            break;
        case IPT_START: // Finished parsing
            if(unset_jxx.size() > 0) {
                cout << "Reach ipt_start and there is still unset jxx instructions" << endl;

                for(auto& i : unset_jxx) {
                    cout << i.second.loc << endl;
                }

                exit(EXIT_FAILURE);
            }

            return;
        }
    }

    cout << "Reached end of file, advanced to far: " << calls << endl;
    exit(EXIT_FAILURE);
}


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

    if(!(line[3] == '1' || line[3] == '2' )) {
        cout << "Unsaported Jmp Found: " << line << endl;
        exit(EXIT_FAILURE);
    }

    u32 pos = 8;

    out.type = JMP;
    out.loc = parse_ip(line, pos);

    pos += 2;

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

