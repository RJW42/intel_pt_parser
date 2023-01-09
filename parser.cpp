#include "types.h"
#include "pt-parse.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char default_data_folder[] = "/home/rjw24/pt-trace-data/";
static const char asm_file_name[]       = "asm-trace.txt";
static const char pt_trace_file_name[]  = "intel-pt-data.pt";
static const char mapping_file_name[]   = "mapping-data.mpt";
static const char out_file_name[]       = "trace.txt";
static const char version_file_name[]   = "trace.info";

u32 get_version_number(const char *verion_file_name);
const char* parse_arguments(int argc, char *argv[]);
char* append_strs(const char* s1, const char* s2);


int main(int argc, char *argv[]) 
{
    const char *data_folder = parse_arguments(argc, argv);

    char *version_file  = append_strs(data_folder, version_file_name);
    char *out_file      = append_strs(data_folder, out_file_name);
    char *mapping_file  = append_strs(data_folder, mapping_file_name);
    char *pt_trace_file = append_strs(data_folder, pt_trace_file_name);
    char *asm_file      = append_strs(data_folder, asm_file_name);

    u32 version = get_version_number(version_file);

    bool use_asm = !(version == 0 || version == 1 || version == 2 || version == 5);

    if (!(version == 0 || version == 1))
        start(
            asm_file, pt_trace_file, 
            mapping_file, out_file, use_asm
        );

    printf("Done\n");
}   


const char* parse_arguments(int argc, char *argv[]) {
    if (argc == 1) {
        return default_data_folder;
    } else if (argc == 2) {
        return argv[1];
    } 

    fprintf(stderr, "Error: expected at max one argument\n");
    fprintf(stderr, "   Ussage: ./parser [parsing data location]\n");
    exit(EXIT_FAILURE);
    return NULL;
}

char* append_strs(const char* s1, const char* s2) {
    int s1_len = strlen(s1);
    int s2_len = strlen(s2);

    char* output = (char*) calloc(s1_len + s2_len + 2, sizeof(char));

    strcpy(output, s1);
    
    if(output[s1_len - 1] != '/') {
        output[s1_len] = '/';
    }

    strcat(output, s2);

    return output;
}


u32 get_version_number(const char *verion_file_name) 
{
    FILE* version_file = fopen(verion_file_name, "r");

    if(version_file == NULL) {
        fprintf(stderr, 
            "Failed to open version file: %s\n", verion_file_name
        );
        exit(EXIT_FAILURE);
    }

    u32 version; 

    fscanf(version_file, "version: %u", &version);

    return version;
}
