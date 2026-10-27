#include "core.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

static int hexval(int c)
{
    if (c >= 0 && c <= 9)
    {
        return c - '0';
    }
    c = tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    return -1;
}

bool load_key(const char* keyfile, uint8_t* key)
{
    FILE* f = fopen(keyfile, "r");
    if (!f)
    {
        perror("Error: fopen()");
        return false;
    }

    uint8_t text[66];
    size_t n = fread(text, 1, sizeof text, f);
    fclose(f);

    if (!(n == 64 || (n == 65 && text[64] == '\n')))
    {
        fprintf(stderr, "Error: file must be 64 characters\n");
        OPENSSL_cleanse(text, sizeof text);
        return false;
    }

    for (int i = 0; i < KEY_SIZE; ++i)
    {
        int first = hexval((int)text[2 * i]);
        int second = hexval((int)text[2 * i + 1]);
        if (first < 0 || second < 0)
        {
            fprintf(stderr, "Error: file must only contain hex characters\n");
            OPENSSL_cleanse(text, sizeof text);
            OPENSSL_cleanse(key, KEY_SIZE);
            return false;
        }
        key[i] = (uint8_t)((first * 16) + second);
    }

    OPENSSL_cleanse(text, sizeof text);

    return true;
}

static void write_u32(uint8_t* buf, uint32_t val) {}

static void write_u64(uint8_t* buf, uint64_t val) {}

bool seal_packet(const uint8_t* key, uint32_t node_id, uint64_t seq_num,
                 const uint8_t* msg, size_t msg_size, uint8_t* packet,
                 size_t* packet_size)
{
    *packet_size = 0;
    if (msg_size == 0 || msg_size > MAX_MESSAGE_SIZE)
    {
        return false;
    }

    write_u32(packet, node_id);
    write_u64(packet + 4, seq_num);
    bool ok = false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        goto out;
    }

    // nonce len defaults to 12, so it only takes header bytes from packet
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, packet) != 1)
    {
        goto out;
    }

    int len = 0;
    // feeds header bytes as aad
    if (EVP_EncryptUpdate(ctx, NULL, &len, packet, HEADER_LEN) != 1)
    {
        goto out;
    }

    if (EVP_EncryptUpdate(ctx, packet + HEADER_LEN, &len, msg, (int)msg_size) !=
        1)
    {
        goto out;
    }

    if (len != (int)msg_size)
    {
        goto out;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, packet + HEADER_LEN + len, &final_len) != 1)
    {
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                            packet + HEADER_LEN + msg_size) != 1)
    {
        goto out;
    }

    *packet_size = HEADER_LEN + msg_size + TAG_LEN;
    ok = true;

out:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
    {
        OPENSSL_cleanse(packet, HEADER_LEN + MAX_MESSAGE_SIZE + TAG_LEN);
    }
    return ok;
}

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