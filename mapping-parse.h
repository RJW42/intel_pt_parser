#ifndef MAPPING_PARSE_H_
#define MAPPING_PARSE_H_

#include "types.h"

u64 get_mapping(u64 host_pc);
void load_mapping_file(const char *file_name);

#endif