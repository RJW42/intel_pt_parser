#include "qemu-source-parse-internal.h"
#include "qemu-source-parse.h"
#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <cstring>

static std::map<u64, qemu_helper_function> qemu_functions;
static std::map<u64, qemu_asm_instruction> qemu_instructions;
static std::unordered_map<std::string, u64> qemu_translated_functions;


void qemu_source_init(
    const char* qemu_source_file_name, 
    const char* translated_source_file_name
) {
    // Keep track of all helper functions called by the guest program
    std::unordered_set<std::string> helpers_to_translate;

    search_for_helper_calls(
        translated_source_file_name, 
        helpers_to_translate
    );

    // Parse all helper functions
    auto& translated_functions = qemu_translated_functions;

    std::cout 
        << " -------- Translating Qemu Helpers -------- " 
        << std::endl << std::endl;

    parse_helper_calls(
        qemu_source_file_name, helpers_to_translate,
        translated_functions
    ); 

    std::cout 
        << " -------- Finished --------"
        << std::endl << std::endl;
}




// Inital Parsing

static void search_for_helper_calls(
    const char* translated_source_file_name, 
    std::unordered_set<std::string>& helpers_to_translate
) {
    auto asm_file = std::ifstream(translated_source_file_name);
    std::string line;

    while(getline(asm_file, line)) {
        if(!line.starts_with("CALL: ")) continue;
        // extract the name of the helper call from the call instruction
        line.erase(0, 6);
        line.erase(0, line.find(" ") + 1);        

        if(helpers_to_translate.find(line) != helpers_to_translate.end())
            continue;

        helpers_to_translate.insert("helper_" + line);
    }
}



static void parse_helper_calls(
    const char* qemu_source_file_name,
    std::unordered_set<std::string>& functions_to_translate,
    std::unordered_map<std::string, u64>& translated_functions
) {
    while(functions_to_translate.size() > 0) {
        // Get function name
        auto helper = *functions_to_translate.begin();
        functions_to_translate.erase(helper);

        // Find this function in qemu source
        auto qemu_file = std::ifstream(qemu_source_file_name);
        std::string line;
        bool found = false;
        std::string name = " <" + helper + ">:";

        while(!found && getline(qemu_file, line))
            found = ends_with(line, name);

        if(!found) {
            std::cout << "Failed to find function in qemu source: " 
                      << helper << std::endl;
            exit(EXIT_FAILURE);
        }   

        std::cout << "QEMU FUNC: " << helper;

        qemu_helper_function func;
        func.start = 0;
        func.size = 0;
        func.name = new std::string(helper);

        qemu_asm_instruction instr(OTHER, 0);

        // Parse this helper function
        while(getline(qemu_file, line) && line.size() > 1) {
            // Parse this line
            instr = parse_line(
                line, functions_to_translate, translated_functions
            );

            if(func.start == 0) {
                // Set the function start point and save it
                func.start = instr.loc;
                std::cout << " start: " << std::hex << func.start << std::endl;
                qemu_functions[func.start] = func;
            }

            // Save this instruction if needed
            if(instr.type != OTHER)
                qemu_instructions[instr.loc] = instr;

            // Print debug information
            switch(instr.type){
            case CALL:
                std::cout << "  call: ";
                goto print_loc;
            case JXX:
                std::cout << "  jxx: ";
                goto print_loc;
            case JMP:
                std::cout << "  jmp: ";
            print_loc:
                std::cout 
                    << instr.loc << " -> " 
                    << (instr.des ? (to_hex(*instr.des)) : "computed" )
                    << std::endl;                           
                break;
            case RET:
                std::cout << "  return" << std::endl;
                break;
            case OTHER:
                break;
            }
        }

        // Set function size
        func.size = instr.loc - func.start + 1;

        std::cout << "END size: " << std::to_string(func.size) << std::endl << std::endl;
    }
}


static qemu_asm_instruction parse_line(
    std::string line, std::unordered_set<std::string>& functions_to_translate,
    std::unordered_map<std::string, u64>& translated_functions
) {
    // Get instruction address
    auto trimed_line = ltrim(line);
    auto adr_string = trimed_line.substr(0, trimed_line.find(":"));
    auto instr_adr = stoul(adr_string, NULL, 16);

    // Get instruction type
    qemu_asm_type type = parse_line_type(line);

    if(type == OTHER || type == RET) {
        return qemu_asm_instruction(type, instr_adr);
    }

    // Check if this jump / call is a computed jump / call
    line = line.erase(0, 32);
    
    auto 
        des_string = ltrim(line.erase(0, line.find(" ")));
        des_string = des_string.substr(0, des_string.find(" "));

    if(!is_hex(des_string)) {
        // Jump / call is computed cannot determine desitination
        return qemu_asm_instruction(type, instr_adr, std::nullopt);
    }

    // Not computed, can determine return address
    auto jmp_des = stoul(des_string, NULL, 16);

    if(type == JMP || type == JXX) {
        return qemu_asm_instruction(type, instr_adr, { jmp_des } );
    }

    // Determine the name of the function being called
    auto 
        call_name = line.substr(line.find("<") + 1);
        call_name = call_name.substr(0, call_name.find(">"));

    // Check if we still need to translate this function
    if (functions_to_translate.find(call_name) == functions_to_translate.end() &&
        translated_functions.find(call_name) == translated_functions.end()
    ){
        functions_to_translate.insert(call_name);
    }

    return qemu_asm_instruction(type, instr_adr, { jmp_des });
}


static qemu_asm_type parse_line_type(std::string line)
{
    // Check for empty line
    if(line.size() < 32) return OTHER;

    // Get the type string
    line = line.erase(0, 32);
    line = line.substr(0, line.find(" "));

    if(line.starts_with("call")) {
        return CALL;
    }
    if(line.starts_with("ret")) {
        return RET;
    }
    if(line.starts_with("jmp")) {
        return JMP;
    }
    if(line.starts_with("j")) {
        return JXX;
    }

    return OTHER;
}


static void find_and_parse_jump_region(
    const char* qemu_source_file_name, u64 jump_loc, 
    std::unordered_map<std::string, u64>& translated_functions
) {
    // Todo: find the untranslated function relating to this 
    //       jump location then translate it 

    // Get the hex string of the jump location
    std::string jump_loc_string = to_hex(jump_loc) + ":";

    // Search for the function containing the jump location
    std::optional<std::string> current_function;
    auto qemu_file = std::ifstream(qemu_source_file_name);
    std::string line;

    std::cout << "UNTRANSLATED QEMU LOC: " << jump_loc_string << std::endl;

    while(getline(qemu_file, line)) {
        // Check if entering new function
        if(line.starts_with("00") && line.find("<") != std::string::npos) {
            std::string 
                func_name = line.erase(0, line.find("<") + 1);
                func_name = func_name.erase(func_name.find(">"));

            current_function = { func_name };
            continue;
        };
        
        // Check if leaving current function
        if(line.size() <= 1) {
            current_function = std::nullopt;
            continue;
        }

        // Check if this line is the one we are looking for
        line = ltrim(line);

        if(!line.starts_with(jump_loc_string)) {
            continue;
        }

        if(!current_function) {
            // There is no function for this line
            std::cout << "  ERROR: No function for jump location: " << jump_loc_string << std::endl;
            exit(EXIT_FAILURE);
        }

        break;
    }

    if(!current_function) {
        std::cout << "  ERROR: jump location not found: " << jump_loc_string << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout 
        << "  FOUND FUNC: " << *current_function  << " TRANSLATING"
        << std::endl << std::endl;

    // Found the function translate it 
    std::unordered_set<std::string> functions_to_translate;

    functions_to_translate.insert(*current_function);

    parse_helper_calls(
        qemu_source_file_name,
        functions_to_translate,
        translated_functions
    );
}


static std::optional<qemu_helper_function> get_corisponding_func(u64 loc)
{
    auto low = qemu_functions.upper_bound(loc);

    if(low == qemu_functions.begin()) {
        return std::nullopt;
    }
    low--;

    if(!(loc < (low->first + low->second.size))) {
        return std::nullopt;
    }

    return {low->second};
}


static std::string to_hex(u64 num) 
{
    std::ostringstream ss;
    ss << std::hex << num;
    return ss.str();
}



// Helper functions
static inline bool ends_with(
    std::string const & value, std::string const & ending
) {
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}


static std::string ltrim(const std::string &s)
{
    size_t start = s.find_first_not_of(" ");
    return (start == std::string::npos) ? "" : s.substr(start);
}


static bool is_hex(std::string const& s)
{
  return s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}