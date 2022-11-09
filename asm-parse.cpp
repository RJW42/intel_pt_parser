#include "asm-parse-internal.h"
#include "asm-parse.h"

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
static std::map<u64, jmp> jmps;

void asm_init(const char* asm_file_name) 
{
    asm_file = std::ifstream(asm_file_name);
}

/* ***** JMP Management ***** */

jmp get_next_jmp(u64 current_ip) 
{
    using namespace std;
    auto low = jmps.lower_bound(current_ip);

    if(low == jmps.end()) {
        printf("Failed to find next jump for: %lX\n", current_ip); 
        exit(EXIT_FAILURE);
    }

    // printf(" Found: %lX\n", low->first);

    return low->second;
}


/* ***** Parsing ***** */

static bool parse_block(std::string& line, trace_element& out);
static bool parse_jmp(std::string& line, trace_element& out);
static bool parse_jxx(std::string& line, trace_element& out);
static bool parse_update(std::string& line, trace_element& out);
static bool parse_label(std::string& line, trace_element& out);
static bool parse_ipt_start(std::string& line, trace_element& out);
static bool parse_ipt_stop(std::string& line, trace_element& out);


void advance_to_mode(void)
{
    using namespace std;
    string line;

    /* Track jumps waiting for a label*/
    unordered_map<int, trace_element> unset_jxx; 

    while(getline(asm_file, line)) {
        trace_element curr;

        if(parse_block(line, curr)) {
#ifdef ASM_PARSE_DEBUG_
            printf("BLOCK: 0x%lX\n", curr.data.block_ip);
#endif
            // Don't need to do anything in perticular for a block
            //  todo: is this true, maybe want to check if there
            //        are unset jumps 
            continue;
        } else if(parse_jmp(line, curr)) {
#ifdef ASM_PARSE_DEBUG_
            printf("  JMP: 0x%lX -> 0x%lX\n", curr.data.jmp.loc, curr.data.jmp.des);
#endif
            // Store jmp
            jmps[curr.data.jmp.loc] = {curr.data.jmp.loc, curr.data.jmp.des, false};
        } else if(parse_jxx(line, curr)) {
#ifdef ASM_PARSE_DEBUG_
            printf("  JXX: 0x%lX -> %u\n", curr.data.jxx.loc, curr.data.jxx.id);
#endif
            // Store this JXX until a label is found     
            if(unset_jxx.find(curr.data.jxx.id) != unset_jxx.end()) {
                cout << "Error label already in use for jxx: " << line << endl;
                exit(EXIT_FAILURE);
            }

            unset_jxx[curr.data.jxx.id] = curr;      
            continue;
        } else if(parse_update(line, curr)) {
#ifdef ASM_PARSE_DEBUG_
            printf("  UPDATE: 0x%lX -> 0x%lX\n", curr.data.update.loc, curr.data.update.new_des);
#endif
            // Update jmp
            jmps[curr.data.update.loc] = {curr.data.update.loc, curr.data.update.new_des, jmps[curr.data.update.loc].conditional};
        } else if(parse_label(line, curr)) {
#ifdef ASM_PARSE_DEBUG_
            printf("  LBL: %u -> 0x%lX\n", curr.data.label.id, curr.data.label.loc);
#endif      
            // Use this label to update any jxx insutrctions
            if(unset_jxx.find(curr.data.label.id) == unset_jxx.end()) {
                cout << "Error label does not have corrisponding jmp: " << line << endl;
                exit(EXIT_FAILURE);
            }

            // Store jmp
            trace_element jxx = unset_jxx[curr.data.label.id];
            jmps[jxx.data.jxx.loc] = {jxx.data.jxx.loc, curr.data.label.loc, true};
            unset_jxx.erase(curr.data.label.id);
            continue;
        } else if(parse_ipt_start(line, curr)) {
#ifdef ASM_PARSE_DEBUG_ 
            printf("IPT_START:\n\n");
#endif      
            if(unset_jxx.size() > 0) {
                cout << "Reach ipt_start and there is still unset jxx instructions" << endl;
                exit(EXIT_FAILURE);
            }

            // Finished parsing for now
            return;
        } else if(parse_ipt_stop(line, curr)) {
// #ifdef ASM_PARSE_DEBUG_
//             printf("IPT_STOP:\n");
// #endif      
            continue;
        } else {
            cout << "Error Unkownn String: " << line << endl;
            exit(EXIT_FAILURE);
        }
    }
}


static inline bool parse_block(std::string& line, trace_element& out) 
{
    using namespace std;
    if(!line.starts_with("BLOCK: 0x")) return false;
    line = line.erase(0, 9);

    out.type = BLOCK;
    out.data.block_ip = stoul(line, nullptr, 16);

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
    out.data.jmp.loc = stoul(loc_string, nullptr, 16);
    out.data.jmp.des = stoul(des_string, nullptr, 16);

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
    out.data.jxx.loc = stoul(loc_string, nullptr, 16);
    out.data.jxx.id = stoi(id_string);

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
    out.data.update.loc = stoul(loc_string, nullptr, 16);
    out.data.update.new_des = stoul(des_string, nullptr, 16);

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
    out.data.label.id = stoi(id_string);
    out.data.label.loc = stoul(loc_string, nullptr, 16);

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

