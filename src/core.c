#include "core.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void write_u32(uint8_t* buf, uint32_t val) {}

static void write_u64(uint8_t* buf, uint64_t val) {}

static uint32_t read_u32(uint8_t* buf) {}

static uint64_t read_u64(uint8_t* buf) {}

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

bool open_packet(const uint8_t* key, const uint8_t* packet, size_t packet_size,
                 uint8_t* out_buffer, size_t* out_len)
{
    *out_len = 0;
    if (packet_size < 29 || packet_size > 128)
    {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    bool ok = false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, packet) != 1)
    {
        goto out;
    }

    int len = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &len, packet, HEADER_LEN) != 1)
    {
        goto out;
    }

    const size_t n = packet_size - HEADER_LEN - TAG_LEN;
    if (EVP_DecryptUpdate(ctx, out_buffer, &len, packet + HEADER_LEN, (int)n) !=
        1)
    {
        goto out;
    }

    if ((size_t)len != n)
    {
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            (void*)(packet + HEADER_LEN + len)) != 1)
    {
        goto out;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out_buffer + len, &final_len) != 1)
    {
        goto out;
    }

    *out_len = (size_t)n;
    ok = true;

out:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
    {
        OPENSSL_cleanse(out_buffer, MAX_MESSAGE_SIZE);
    }
    return ok;
}

bool core_encrypt(core_state* core_state, const char* msg, size_t msg_size,
                  uint8_t* packet, size_t* packet_size)
{
    *packet_size = 0;
    if (!core_state->alive)
    {
        return false;
    }
    if (core_state->next_seq_num == UINT64_MAX)
    {
        core_state->alive = false;
        return false;
    }
    uint64_t seq_num = core_state->next_seq_num++;
    if (!seal_packet(core_state->key, core_state->node_id, seq_num, msg,
                     msg_size, packet, packet_size))
    {
        // drops msg if encrypting fails
        return false;
    }
    return true;
}

bool core_decrypt(core_state* core_state, const uint8_t* packet,
                  const size_t packet_size, uint8_t* out_buffer,
                  size_t* out_len)
{
    *out_len = 0;
    if (!core_state->alive)
    {
        return false;
    }
    if (!open_packet(core_state->key, packet, packet_size, out_buffer, out_len))
    {
        return false;
    }
    if (read_u32(packet) == core_state->node_id)
    {
        OPENSSL_cleanse(out_buffer, out_len);
        *out_len = 0;
        return false;
    }
    return true;
}

static bool process_packet(short revents, int in_fd, int out_fd,
                           const char* side, core_state* core_state)
{
    if (!(revents & (POLLIN | POLLHUP | POLLERR)))
    {
        return true;
    }

    uint8_t buf[MAX_PACKET_SIZE];
    ssize_t r = recv(in_fd, buf, MAX_PACKET_SIZE, 0);
    if (r == 0)
    {
        fprintf(stderr, "Error: %s side gone\n", side);
        return false;
    }
    if (r < 0)
    {
        perror("Error: core recv()");
        return false;
    }

    uint8_t out_buffer[MAX_PACKET_SIZE];
    size_t out_len;
    bool ok = false;

    if (!strcmp(side, "red"))
    {
        ok = core_encrypt(core_state, buf, r, out_buffer, &out_len);
    }
    else
    {
        ok = core_decrypt(core_state, buf, r, out_buffer, &out_len);
    }

    if (ok && send(out_fd, out_buffer, out_len, MSG_NOSIGNAL) < 0)
    {
        perror("Error: core send()");
        return false;
    }

    OPENSSL_cleanse(buf, sizeof buf);
    OPENSSL_cleanse(out_buffer, sizeof out_buffer);

    return true;
}

bool core_loop(int red_fd, int black_fd, core_state* core_state,
               const char* keyfile)
{
    if (!load_key(keyfile, core_state->key))
    {
        return false;
    }

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

        if (!process_packet(fds[0].revents, red_fd, black_fd, "red",
                            core_state))
        {
            return false;
        }
        if (!process_packet(fds[1].revents, black_fd, red_fd, "black",
                            core_state))
        {
            return false;
        }
    }
}