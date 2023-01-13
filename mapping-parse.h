#ifndef MAPPING_PARSE_H_
#define MAPPING_PARSE_H_

#include "types.h"
#include "robbin_hood.h"

struct mapping_state_t {
    robin_hood::unordered_flat_map<u64, u64> host_ip_to_guest_ip;
};

u64 get_mapping(mapping_state_t& state, u64 host_pc);
void load_mapping_file(mapping_state_t& state, const char *file_name);

#endif