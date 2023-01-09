#include "mapping-parse.h"
#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#include "robbin_hood.h"

static robin_hood::unordered_flat_map<u64, u64> host_ip_to_guest_ip;

u64 get_mapping(u64 host_pc) 
{
    return host_ip_to_guest_ip[host_pc];   
}


void load_mapping_file(const char *file_name) 
{
    FILE* mapping_data = fopen(file_name, "r");

    if(mapping_data == NULL) {
        fprintf(stderr, "Failed to open data file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    u64 guest_pc;
    u64 host_pc;

    while(fscanf(mapping_data, "%lX, %lX\n", &guest_pc, &host_pc) != EOF) {
        host_ip_to_guest_ip[host_pc] = guest_pc;
    }

    fclose(mapping_data);
}