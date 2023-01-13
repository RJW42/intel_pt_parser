#ifndef PT_PARSE_H_
#define PT_PARSE_H_

void start(
    const char* asm_file, const char* pt_trace_file, 
    const char* mapping_file, const char* out_file, 
    u64 start_offset, u64 end_offset,
    bool use_asm
);

#endif