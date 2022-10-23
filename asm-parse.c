#include "asm-parse-internal.h"
#include "asm-parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>


static FILE* asm_file;


void asm_init(const char* asm_file_name) 
{
    open_asm_file(asm_file_name);
    parse_asm_file();
}


/* ***** Parsing ***** */
static void parse_asm_file()
{
    // File Reading Vars 
    char *line_buffer = NULL;
    size_t buffer_size = 0;
    ssize_t line_length = 0; 

    // Parsing State Vars
    block_type curr_type = UNSET;
    instruction curr_inst;


    while((line_length = getline(&line_buffer, &buffer_size, asm_file)) != - 1) {
        // Remove newline
        if(line_length > 0) line_buffer[line_length - 1] = '\0';

        if(parse_empty_line(line_buffer, line_length)) {
            continue;
        } else if(parse_comment(line_buffer, line_length)) {
            continue;
        } else if(parse_block_break(line_buffer, line_length)) {
            curr_type = UNSET;
            continue;
        } else if(parse_block_type(line_buffer, line_length, &curr_type)) {
            continue;
        } else if(curr_type == OUT && parse_instruction(line_buffer, line_length, &curr_inst)) {
            continue;
        }
    }
}


static inline bool parse_comment(const char *buffer, size_t length)
{
    return (buffer[0] == ' ' && buffer[1] == ' ' && buffer[2] == '-');
}


static inline bool parse_empty_line(const char *buffer, size_t length)
{
    return length < 2;
}


static inline bool parse_block_break(const char* buffer, size_t length) 
{
    return buffer[0] == '-';
}


static inline bool parse_block_type(const char* buffer, size_t length, block_type *curr_type)
{
    if(starts_with(buffer, "IN")) {
        *curr_type = IN;
    } else if(starts_with(buffer, "OUT")) {
        *curr_type = OUT;
    } else if(starts_with(buffer, "PROLOGUE")) {
        *curr_type = PROLOGUE;
    } else {
        return false;
    }
    return true;
}


static inline bool parse_instruction(const char* buffer, size_t length, instruction* inst) 
{
    /* HEX_IP (2:13) : __  */
    if(!(buffer[0] == '0' && buffer[1] == 'x') || length < 22) {
        return false;
    }

    // Get insutrction information 
    inst->ip = parse_instruction_pointer(&buffer[2]);
    inst->type = parse_instruction_type(buffer, length);

    // Parse the instruction data
    switch(inst->type) {
    case JMP:
        inst->data.jmp_location = parse_instruction_pointer(&buffer[51]);
        printf("%s\n", buffer);
    }

    return true;
}


static inline unsigned long parse_instruction_pointer(const char* buffer) 
{
    unsigned long ip = 0;

    for(int i = 0; i <= 12; i++){
        char byte = buffer[i];

        // Convert to number 
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <= 'z') byte = byte - 'a';
        else if (byte >= 'A' && byte <= 'Z') byte = byte - 'A';

        ip = (ip << 4) | (byte & 0xF);

    }

    return ip;
}


static inline instruction_type parse_instruction_type(const char* buffer, size_t length)
{
    if(length < 52) {
        return UNKOWN;
    }

    buffer = &buffer[42];

    if(starts_with(buffer, "jmp ")){
        return JMP;
    }

    return UNKOWN;
}


/* ***** File Management ***** */
static void open_asm_file(const char* file_name)
{
    asm_file = fopen(file_name, "r");

    if(asm_file == NULL) {
        fprintf(stderr, "Failed to open asm file: %s", file_name);
        exit(EXIT_FAILURE);
    }
}


/* ***** Util ***** */

/* Returns true if s1 starts with s2 
 * strings must be terminated with nil */
static bool starts_with(const char *s1, const char *s2)
{
    for(int i = 0; s2[i] != '\0'; ++i){
        if(s1[i] == '\0' || s1[i] != s2[i]) return false;
    }
    return true;
}