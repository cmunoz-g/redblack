#include "core.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

static bool process_packet(short revents, int in_fd, int out_fd,
                           const char* side)
{
    if (!(revents & (POLLIN | POLLHUP | POLLERR)))
    {
        return true;
    }

    char buf[MAX_PACKET_SIZE];
    ssize_t r = recv(in_fd, buf, MAX_PACKET_SIZE, 0);
    if (r == 0)
    {
        fprintf(stderr, "Error: %s side gone", side);
        return false;
    }
    if (r < 0)
    {
        perror("Error: core recv()");
        return false;
    }
    if (send(out_fd, buf, (size_t)r, 0) < 0)
    {
        perror("Error: core send()");
        return false;
    }

    return true;
}

bool core_loop(int red_fd, int black_fd, const char* keyfile)
{
    (void)keyfile;

    struct pollfd fds[2] = {{.fd = red_fd, .events = POLLIN},
                            {.fd = black_fd, .events = POLLIN}};

    for (;;)
    {
        if (poll(fds, 2, -1) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("Error: core poll()");
            return false;
        }

        if (!process_packet(fds[0].revents, red_fd, black_fd, "red"))
        {
            return false;
        }
        if (!process_packet(fds[1].revents, black_fd, red_fd, "black"))
        {
            return false;
        }
    }
}