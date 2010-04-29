#ifndef PROTOHANDLER_H
#define PROTOHANDLER_H

#define MAX_SO_NAME 512

typedef struct {
    char name[MAX_SO_NAME-10];
    void * (*init)(const char* conf_file);
    char * (*process)(void *handler, const char* input);
    int (*free_output)(char *output);
    int (*uninit)(void *handler);
} post_handler_worker_t;

#endif
