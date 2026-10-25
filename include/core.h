#pragma once

#include "stdbool.h"
#include "stdint.h"

#define MAX_PORT 65535
#define MIN_PORT 1024
#define MAX_MESSAGE_SIZE 100
#define MAX_PACKET_SIZE MAX_MESSAGE_SIZE  // todo: change later
#define N_CHILDREN 3

typedef struct
{
    uint16_t red_in_port;
    uint16_t red_out_port;
    uint16_t black_in_port;
    uint16_t black_out_port;
} port_info;

typedef enum
{
    RED_CHILD = 0,
    BLACK_CHILD,
    CORE_CHILD,
} forked_processes;

bool core_loop(int red_fd, int black_fd, const char* keyfile);