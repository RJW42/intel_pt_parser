#ifndef PT_PARSE_H_
#define PT_PARSE_H_

void start(
    const char* asm_file, const char* pt_trace_file, 
    const char* mapping_file, const char* out_file, 
    bool use_asm
);

#endif