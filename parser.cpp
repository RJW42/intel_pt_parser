#include "types.h"
#include "pt-parse.h"

#include <stdio.h>
#include <stdlib.h>


u32 get_version_number(const char *verion_file_name);


int main() 
{
    // TODO: change this to args
    char asm_file[]      = "/home/rjw24/pt-trace-data/asm-trace.txt";
    char pt_trace_file[] = "/home/rjw24/pt-trace-data/intel-pt-data.pt";
    char mapping_file[]  = "/home/rjw24/pt-trace-data/mapping-data.mpt";
    char out_file[]      = "/home/rjw24/pt-trace-data/trace.txt";
    char version_file[]  = "/home/rjw24/pt-trace-data/trace.info";

    u32 version = get_version_number(version_file);

    bool use_asm = !(version == 0 || version == 1 || version == 2);

    if (!(version == 0 || version == 1))
        start(
            asm_file, pt_trace_file, 
            mapping_file, out_file, use_asm
        );

    printf("Done\n");
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
