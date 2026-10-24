#include "core.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define ERR_STR_SIZE ((size_t)64)

bool parse_port(unsigned int* port, char* source, char* err_str)
{
    char* end;
    errno = 0;
    long val = strtol(source, &end, 10);
    if (end == source)
    {
        snprintf(err_str, ERR_STR_SIZE, "Not a number");
        return false;
    }
    if (errno == ERANGE || val < MIN_PORT || val > MAX_PORT)
    {
        snprintf(err_str, ERR_STR_SIZE, "Out of range");
        return false;
    }
    if (*end != '\0')
    {
        snprintf(err_str, ERR_STR_SIZE, "Trailing characters after number");
        return false;
    }
    *port = (int)val;
    return true;
}

bool parse_all_ports(char* argv[], port_info* port_info)
{
    char err_str[ERR_STR_SIZE];
    if (!parse_port(&port_info->red_in_port, argv[2], err_str))
    {
        printf("Error: cannot parse red_in_port: %s\n", err_str);
        return false;
    }
    if (!parse_port(&port_info->red_out_port, argv[3], err_str))
    {
        printf("Error: cannot parse red_out_port: %s\n", err_str);
        return false;
    }
    if (!parse_port(&port_info->black_in_port, argv[4], err_str))
    {
        printf("Error: cannot parse black_in_port: %s\n", err_str);
        return false;
    }
    if (!parse_port(&port_info->black_out_port, argv[5], err_str))
    {
        printf("Error: cannot parse black_out_port: %s\n", err_str);
        return false;
    }
    return true;
}

bool prepare_relay_loop(int* udp_fd, struct sockaddr_in* local,
                        struct sockaddr_in* dest, int listen_port,
                        int send_port)
{
    *udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*udp_fd < 0)
    {
        fprintf(stderr, "Error: Cannot create UDP socket");
        return false;
    }

    int on = 1;
    setsockopt(*udp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    *local = (struct sockaddr_in){.sin_addr = AF_INET,
                                  .sin_port = htons(listen_port),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};

    *dest = (struct sockaddr_in){.sin_addr = AF_INET,
                                 .sin_port = htons(send_port),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};

    if (bind(*udp_fd, (struct sockaddr*)local, sizeof *local) < 0)
    {
        fprintf(stderr, "Error: Cannot bind to UDP socket with port %d\n",
                listen_port);
        return false;
    }

    return true;
}

bool relay_loop(int ipc_fd, uint16_t listen_port, uint16_t send_port)
{
    int udp_fd;
    struct sockaddr_in local;
    struct sockaddr_in dest;
    if (!prepare_relay_loop(&udp_fd, &local, &dest, listen_port, send_port))
    {
        return false;
    }

    struct pollfd fds[2] = {{.fd = ipc_fd, .events = POLLIN},
                            {.fd = udp_fd, .events = POLLIN}};
    char buf[MAX_PACKET_SIZE];

    for (;;)
    {
        if (poll(fds, 2, -1) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("Error: poll");
            return false;
        }

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR))
        {
            ssize_t r = recv(ipc_fd, buf, MAX_PACKET_SIZE, 0);
            if (r == 0)
            {
                fprintf(stderr, "Error: Core connection gone\n");
                return false;
            }
            else if (r < 0)
            {
                perror("Error: recv()");
                return false;
            }
            sendto(udp_fd, buf, (size_t)r, 0, (struct sockaddr*)&dest,
                   sizeof dest);
        }

        if (fds[1].revents & POLLIN)
        {
            ssize_t r = recv(udp_fd, buf, MAX_PACKET_SIZE, MSG_TRUNC);
            if (r < 0 || (size_t)r > MAX_PACKET_SIZE)
            {
                continue;
            }
            if (send(ipc_fd, buf, (size_t)r, 0) < 0)
            {
                fprintf(stderr, "Error: Core connection gone\n");
                return false;
            }
        }
    }

    return true;
}

int main(int argc, char* argv[])
{
    if (argc != 7)
    {
        fprintf(stderr,
                "Error: Not enough arguments\n"
                "Usage: ./redblack <node_id> <red_in_port> <red_out_port>"
                "<black_in_port> <black_out_port> <keyfile>\n");
        exit(EXIT_FAILURE);
    }

    port_info port_info;
    if (!parse_all_ports(argv, &port_info))
    {
        fprintf(stderr,
                "Usage: ./redblack <node_id> <red_in_port> <red_out_port>"
                "<black_in_port> <black_out_port> <keyfile>\n");
        exit(EXIT_FAILURE);
    }
    const char* keyfile = argv[6];

    int red_to_core[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, red_to_core) < 0)
    {
        perror("Error: socketpair():");
        exit(EXIT_FAILURE);
    }

    int black_to_core[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, black_to_core) <
        0)
    {
        perror("Error: socketpair():");
        exit(EXIT_FAILURE);
    }

    pid_t pids[N_CHILDREN];

    for (int i = 0; i < N_CHILDREN; ++i)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("Error: fork()");
            for (int j = 0; j < i; ++j)
            {
                waitpid(pids[j], NULL, 0);
            }
            exit(EXIT_FAILURE);
        }
        if (pid == 0)
        {
            bool ok = false;
            switch (i)
            {
                case RED_CHILD:
                {
                    close(red_to_core[1]);
                    close(black_to_core[0]);
                    close(black_to_core[1]);
                    ok = relay_loop(red_to_core[0], port_info.red_in_port,
                                    port_info.red_out_port);
                    break;
                }
                case BLACK_CHILD:
                {
                    close(black_to_core[1]);
                    close(red_to_core[0]);
                    close(red_to_core[1]);
                    ok = relay_loop(black_to_core[0], port_info.black_in_port,
                                    port_info.black_out_port);
                    break;
                }
                case CORE_CHILD:
                {
                    close(red_to_core[0]);
                    close(black_to_core[0]);
                    core_loop();  // todo
                    break;
                }
            }
            _exit(ok);
        }
        pids[i] = pid;
    }

    close(red_to_core[0]);
    close(red_to_core[1]);
    close(black_to_core[0]);
    close(black_to_core[1]);

    // todo : wait on children

    return 0;
}