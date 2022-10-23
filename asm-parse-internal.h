#ifndef ASM_PARSE_INTERNAL_H_
#define ASM_PARSE_INTERNAL_H_

#include <stdio.h>
#include <stdbool.h>

typedef enum block_type {
    IN,
    OUT,
    PROLOGUE,
    UNSET
} block_type;

typedef enum instruction_type {
    UNKOWN,
    JMP
} instruction_type;


typedef struct instruction {
    unsigned long ip;
    instruction_type type;
    union {
        unsigned long jmp_location;
    } data;
} instruction;


static void open_asm_file(const char* file_name);

static void parse_asm_file();

static bool parse_empty_line(const char *buffer, size_t length);
static bool parse_comment(const char* buffer, size_t length);
static bool parse_block_break(const char* buffer, size_t length);
static bool parse_block_type(const char* buffer, size_t length, block_type *curr_type);

static bool parse_instruction(const char* buffer, size_t length, instruction *inst);
static unsigned long parse_instruction_pointer(const char* buffer);
static instruction_type parse_instruction_type(const char* buffer, size_t length);


static bool starts_with(const char *s1, const char *s2);
#endif