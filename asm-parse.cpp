#include "asm-parse-internal.h"
#include "asm-parse.h"
#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

//#define ASM_PARSE_DEBUG_

static std::ifstream asm_file;
static std::map<u64, jit_asm_instruction*> instructions;
static std::map<u64, u64> block_sizes;

void asm_init(const char* asm_file_name) 
{
    asm_file = std::ifstream(asm_file_name);
}

#define PARSE_ELEMENT(x, y, z) \
    if(parse_ ## x(y, z)) return true

/* ***** JMP Management ***** */

jit_asm_instruction* get_next_jit_instr(u64 current_ip)
{
    using namespace std;
    auto low = instructions.lower_bound(current_ip);

    if(low == instructions.end()) {
        printf("Failed to find next instruction for: %lX\n", current_ip); 
        exit(EXIT_FAILURE);
    }

    return low->second;
}

u64 get_last_jmp_loc(void) 
{
    return (--instructions.end())->second->des;
}


bool ip_inside_block(u64 ip) 
{
    using namespace std;
    auto block = block_sizes.find(ip);

    if(block != block_sizes.end()) { 
#ifdef ASM_PARSE_DEBUG_
        printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, block->first);
#endif
        return true;
    }

    auto low = block_sizes.upper_bound(ip);

    if(low == block_sizes.begin()) {
        return false;
    }
    low--;

    if(!(ip < (low->first + low->second))) {
        return false;
    }

#ifdef ASM_PARSE_DEBUG_
    printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, low->first);
#endif

    return true;
}


/* ***** Parsing ***** */

void advance_to_mode(void)
{
    using namespace std;
    string line;
    static int calls = 0;
    calls++;

    /* Track jumps waiting for a label*/
    unordered_map<int, trace_element> unset_jxx; 
    u64 current_block = 0;

    while(getline(asm_file, line)) {
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
            current_block = curr.block_ip;
            //  todo: maybe want to check if there if there are unset jumps 
            break;
        case BLOCK_SIZE: // Record block size
            if(current_block == 0) {
                printf("    Error found block size without a block to map too\n");
                exit(EXIT_FAILURE);
            }

            block_sizes[current_block] = curr.block_size;
            current_block = 0;
            break;
        case JMP: // Store jmp
            instructions.emplace(curr.jmp.loc, new jit_asm_instruction(
                JIT_JMP, curr.jmp.loc, curr.jmp.des
            ));
            break;
        case JXX: // Store this JXX until a label is found
            if(unset_jxx.find(curr.jxx.id) != unset_jxx.end()) {
                cout << "Error label already in use for jxx: " << line << endl;
                exit(EXIT_FAILURE);
            }

            unset_jxx[curr.jxx.id] = curr; 
            break;
        case JXX_LDST: // Store jmp
            instructions.emplace(curr.jmp.loc, new jit_asm_instruction(
                JIT_JXX, curr.jxx_ldst.loc, curr.jxx_ldst.des
            ));
            break;
        case CALL: // Store call
            instructions.emplace(curr.call.loc, new jit_asm_instruction(
                JIT_CALL, curr.call.loc, curr.call.is_breakpoint
            ));
            break;
        case UPDATE: // Update jmp
            instructions[curr.update.loc]->des = curr.update.new_des;
            break;
        case LABEL: {// Use this label to update any jxx insutrctions
            if(unset_jxx.find(curr.label.id) == unset_jxx.end()) {
                cout 
                    << "Error label does not have corrisponding jmp: " 
                    << line << endl;
                exit(EXIT_FAILURE);
            }

            trace_element jxx = unset_jxx[curr.label.id];
            
            instructions.emplace(jxx.jxx.loc, new jit_asm_instruction(
                JIT_JXX, jxx.jxx.loc, curr.label.loc
            ));

            unset_jxx.erase(curr.label.id);
            break;
        } case IPT_STOP:
            break;
        case IPT_START: // Finished parsing
            if(unset_jxx.size() > 0) {
                cout << "Reach ipt_start and there is still unset jxx instructions" << endl;
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
        printf("  JMP: 0x%lX -> 0x%lX\n", elmnt.jmp.loc, elmnt.jmp.des);
        break;
    case JXX:
        printf("  JXX: 0x%lX -> %u\n", elmnt.jxx.loc, elmnt.jxx.id);
        break;
    case JXX_LDST:
        printf("  JXX_LDST: 0x%lX -> 0x%lX\n", elmnt.jxx_ldst.loc, elmnt.jxx_ldst.des);
        break;
    case UPDATE:
        printf("  UPDATE: 0x%lX -> 0x%lX\n", elmnt.update.loc, elmnt.update.new_des);
        break;
    case LABEL:
        printf("  LBL: %u -> 0x%lX\n", elmnt.label.id, elmnt.label.loc);
        break;
    case CALL:
        std::cout 
            << "  CALL: 0x" << std::uppercase << std::hex << elmnt.call.loc
            << " -> " << (elmnt.call.is_breakpoint ? "BreakPoint" : "QEMU")
            << std::endl;
        break;
    case IPT_START:
        printf("IPT_START:\n\n");
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
    PARSE_ELEMENT(jxx, l, o);
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
    out.jmp.loc = parse_ip(line, pos);

    pos += 2;

    out.jmp.des = parse_ip(line, pos);

    return true;
}


static inline bool parse_jxx(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX: 0x")) return false;
    // JXX: 0x... .

    u32 pos = 7;
    
    out.type = JXX;
    out.jxx.loc = parse_ip(line, pos); 
    out.jxx.id = parse_id(line, pos); 

    return true;
}

static inline bool parse_jxx_ldst(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX_LDST: 0x")) return false;
    // JXX_LDST: 0x... 0x...

    u32 pos = 12;
    
    out.type = JXX_LDST;
    out.jxx_ldst.loc = parse_ip(line, pos);

    pos += 2;

    out.jxx_ldst.des = parse_ip(line, pos);

    return true;
}


static inline bool parse_update(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("UPDATE: 0x")) return false;
    // UPDATE: 0x... 0x...

    u32 pos = 10;

    out.type = UPDATE;
    out.update.loc = parse_ip(line, pos); 

    pos += 2;

    out.update.new_des = parse_ip(line, pos);

    return true;
}

static inline bool parse_label(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("LBL: ")) return false;
    // LBL: . 0x...

    u32 pos = 5;

    out.type = LABEL;
    out.label.id = parse_id(line, pos); 
    out.label.loc = parse_ip(line, pos);

    return true;
}


static inline bool parse_call(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("CALL: 0x")) return false;
    // CALL: 0x... .str.
    u32 pos = 8;

    out.type = CALL;
    out.call.loc = parse_ip(line, pos); 

    string func_string = line.substr(pos);

    out.call.qemu_des = 0; // get_call_loc(func_string);
    out.call.is_breakpoint = func_string.compare("ctrace_ipt_breakpoint") == 0;

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
    line.erase(0, 12);

    out.type = BLOCK_SIZE;
    out.block_size = stol(line);

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

