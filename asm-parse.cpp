#include "qemu-source-parse.h"

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

#define ASM_PARSE_DEBUG_

static std::ifstream asm_file;
static std::map<u64, jit_asm_instruction> instructions;
static std::map<u64, u64> block_sizes;

void asm_init(const char* asm_file_name) 
{
    asm_file = std::ifstream(asm_file_name);
}

#define PARSE_ELEMENT(x, y, z) \
    if(parse_ ## x(y, z)) return true

/* ***** JMP Management ***** */

jit_asm_instruction get_next_jit_instr(u64 current_ip)
{
    using namespace std;
    auto low = instructions.lower_bound(current_ip);

    if(low == instructions.end()) {
        printf("Failed to find next instruction for: %lX\n", current_ip); 
        exit(EXIT_FAILURE);
    }

    return low->second;
}


bool ip_inside_block(u64 ip) 
{
    using namespace std;
    auto block = block_sizes.find(ip);

    if(block != block_sizes.end()) { 
        printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, block->first);
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

    printf("    INSIDE JIT: 0x%lX -> 0x%lX\n", ip, low->first);

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
            instructions.emplace(curr.jmp.loc, jit_asm_instruction(
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
            instructions.emplace(curr.jmp.loc, jit_asm_instruction(
                JIT_JXX, curr.jxx_ldst.loc, curr.jxx_ldst.des
            ));
            break;
        case CALL: // Store call
            instructions.emplace(curr.call.loc, jit_asm_instruction(
                JIT_CALL, curr.call.loc, curr.call.qemu_des
            ));
            break;
        case UPDATE: // Update jmp
            instructions[curr.update.loc] = jit_asm_instruction(
                instructions.find(curr.update.loc)->second.type,
                curr.update.loc, curr.update.new_des
            );
            break;
        case LABEL: {// Use this label to update any jxx insutrctions
            if(unset_jxx.find(curr.label.id) == unset_jxx.end()) {
                cout 
                    << "Error label does not have corrisponding jmp: " 
                    << line << endl;
                exit(EXIT_FAILURE);
            }

            trace_element jxx = unset_jxx[curr.label.id];
            
            instructions.emplace(jxx.jxx.loc, jit_asm_instruction(
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
            << " -> " << get_call_name(elmnt.call.qemu_des)
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
    line = line.erase(0, 9);

    out.type = BLOCK;
    out.block_ip = stoul(line, nullptr, 16);

    return true;
}


static inline bool parse_jmp(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("JMP")) return false;
    line = line.erase(0, 3);

    if(!(line[0] == '1' || line[0] == '2' )) {
        cout << "Unsaported Jmp Found: " << line << endl;
        exit(EXIT_FAILURE);
    }

    line = line.erase(0, 5);
    
    string loc_string = line.substr(0, line.find(" "));
    string des_string = line.erase(0, loc_string.length() + 3);

    out.type = JMP;
    out.jmp.loc = stoul(loc_string, nullptr, 16);
    out.jmp.des = stoul(des_string, nullptr, 16);

    return true;
}


static inline bool parse_jxx(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX: 0x")) return false;
    line = line.erase(0, 7);

    string loc_string = line.substr(0, line.find(" "));
    string id_string = line.erase(0, loc_string.length() + 1);
    
    out.type = JXX;
    out.jxx.loc = stoul(loc_string, nullptr, 16);
    out.jxx.id = stoi(id_string);

    return true;
}

static inline bool parse_jxx_ldst(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("JXX_LDST: 0x")) return false;
    line = line.erase(0, 12);

    string loc_string = line.substr(0, line.find(" "));
    string des_string = line.erase(0, loc_string.length() + 3);
    
    out.type = JXX_LDST;
    out.jxx_ldst.loc = stoul(loc_string, nullptr, 16);
    out.jxx_ldst.des = stoul(loc_string, nullptr, 16);

    return true;
}


static inline bool parse_update(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("UPDATE: 0x")) return false;
    line = line.erase(0, 10);
    
    string loc_string = line.substr(0, line.find(" "));
    string des_string = line.erase(0, loc_string.length() + 3);

    out.type = UPDATE;
    out.update.loc = stoul(loc_string, nullptr, 16);
    out.update.new_des = stoul(des_string, nullptr, 16);

    return true;
}

static inline bool parse_label(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("LBL: ")) return false;
    line = line.erase(0, 5);

    string id_string = line.substr(0, line.find(" "));
    string loc_string = line.erase(0, id_string.length() + 1);

    out.type = LABEL;
    out.label.id = stoi(id_string);
    out.label.loc = stoul(loc_string, nullptr, 16);

    return true;
}


static inline bool parse_call(std::string& line, trace_element& out)
{
    using namespace std;
    if(!line.starts_with("CALL: 0x")) return false;
    line = line.erase(0, 8);

    string loc_string = line.substr(0, line.find(" "));
    string func_string = 
        "helper_" + line.erase(0, loc_string.length() + 1);

    out.type = CALL;
    out.call.loc = stoul(loc_string, nullptr, 16);
    out.call.qemu_des = get_call_loc(func_string);

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

