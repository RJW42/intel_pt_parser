#include "types.h"
#include "pt-parse.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <cerrno>

#define BUFFER_SIZE 1024

static const char default_data_folder[] = "/home/rjw24/pt-trace-data/";
static const char asm_file_name[]       = "asm-trace.txt";
static const char pt_trace_file_name[]  = "data.pt";
static const char mapping_file_name[]   = "mapping.txt";
static const char out_file_name[]       = "trace.txt";
static const char version_file_name[]   = "trace.info";

u32 get_version_number(const char *verion_file_name);
u64 get_file_size(const char *file_name);
const char* parse_arguments(int argc, char *argv[]);
char* append_strs(const char* s1, const char* s2);
char* append_num(const char* s1, u32 number);

void* run_start(void* _args);
void run_concurrently(
    u32 num_threads, char *out_file, char *mapping_file, 
    char *pt_trace_file, bool use_asm, u64 file_size
);

struct start_args {
    char *out_file;
    char *mapping_file;
    char *pt_trace_file;
    char *asm_file;
    bool use_asm;
    u64 start_offset;
    u64 end_offset;
};


int main(int argc, char *argv[]) 
{
    const char *data_folder = parse_arguments(argc, argv);

    char *out_file      = append_strs("./", out_file_name);
    char *mapping_file  = append_strs(data_folder, mapping_file_name);
    char *pt_trace_file = append_strs(data_folder, pt_trace_file_name);

    u64 file_size = get_file_size(pt_trace_file);

    bool use_asm = false;
    int num_threads = 6;

    run_concurrently(
        num_threads, out_file, mapping_file,
        pt_trace_file, use_asm, file_size
    );

    // start(
    //     nullptr, pt_trace_file, 
    //     mapping_file, out_file, 
    //     0, file_size, use_asm
    // );

    printf("Done\n");
}   

void run_concurrently(
    u32 num_threads, char *out_file, char *mapping_file, 
    char *pt_trace_file, bool use_asm, u64 file_size
) {
    pthread_t *threads = (pthread_t*) calloc(num_threads, sizeof(pthread_t));
    start_args *args = (start_args*) calloc(num_threads, sizeof(start_args));

    u64 chunk_size = file_size / num_threads;
    u64 previous_end = 0;

    // Generate sub traces 
    for (u32 i = 0; i < num_threads; i++) {
        char* thread_out_file = append_num(out_file, i);

        u64 start_offset = previous_end;
        u64 end_offset = (i == num_threads - 1) ? 
            file_size : start_offset + chunk_size;
        
        previous_end = end_offset;

        args[i].mapping_file = mapping_file;
        args[i].pt_trace_file = pt_trace_file;
        args[i].asm_file = nullptr;
        args[i].use_asm = use_asm;
        args[i].start_offset = start_offset;
        args[i].end_offset = end_offset;
        args[i].out_file = thread_out_file;

        pthread_create(
            &threads[i], NULL, run_start, &args[i]
        );
    }

    // Wait for completion
    FILE *complete_trace_file = fopen(out_file, "w");

    for (u32 i = 0; i < num_threads; i++) {
        void *ret;
        pthread_join(threads[i], &ret);

        char command[1024];

        snprintf(command, 1024, "cat %s >> %s", args[i].out_file, out_file);

        system(command);
    }

    fclose(complete_trace_file);
}


void* run_start(void* _args) {
    start_args* args = (start_args*) _args;

    start(
        args->asm_file, 
        args->pt_trace_file, 
        args->mapping_file, 
        args->out_file, 
        args->start_offset,
        args->end_offset,
        args->use_asm
    );

    pthread_exit(NULL);
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

char* append_num(const char* s1, u32 number) {
    int s1_len = strlen(s1);
    int out_len = s1_len + 10;

    char* output = (char*) calloc(out_len, sizeof(char));

    sprintf(output, "%s.%u", s1, number);

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


u64 get_file_size(const char *file_name) 
{
    FILE *fp = fopen(file_name, "rb");   

    if(!fp) {
        fprintf(stderr, "Failed to open file %s to read size %s\n", file_name, strerror(errno));
    }

    fseek(fp, 0L, SEEK_END);
    u64 size = ftell(fp);

    fclose(fp);

    return size;
}
