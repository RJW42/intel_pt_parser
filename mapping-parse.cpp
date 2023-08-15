#include "mapping-parse.h"
#include "types.h"

#include <stdio.h>
#include <stdlib.h>
#include <cerrno>

u64 get_mapping(mapping_state_t& state, u64 host_pc) 
{
    return state.host_ip_to_guest_ip[host_pc];   
}


void load_mapping_file(mapping_state_t& state, const char *file_name) 
{
    FILE* mapping_data = fopen(file_name, "r");

    if(mapping_data == NULL) {
        fprintf(stderr, "Failed to open mapping file: %s, reason: %s\n", file_name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    u64 guest_pc;
    u64 host_pc;

    while(fscanf(mapping_data, "%lX, %lX\n", &guest_pc, &host_pc) != EOF) {
        state.host_ip_to_guest_ip[host_pc] = guest_pc;
    }

    fclose(mapping_data);
}