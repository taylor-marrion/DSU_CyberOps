// beacon.c - Safe simulated HTTP beacon for CSC840 Lab 15 (FINAL)
// Harmless by design:
//   - localhost-only C2 (127.0.0.1:8080)
//   - no persistence
//   - no command execution
//   - no data exfiltration
//
// This program is intentionally designed for
// defensive malware analysis and reverse-engineering education.
//
// Build modes:
//   plaintext         : no encoding (easy RE / baseline)
//   encoded           : XOR-encoded config, decoded at runtime
//   encoded_stripped  : encoded + stripped symbols (harder RE)

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* =========================
 * Configuration
 * ========================= */
#define XOR_KEY     0x2A
#define C2_IP       "127.0.0.1"
#define C2_PORT     8080
#define MAX_ITERS   5
#define MAX_SLEEP_S 30

/* =========================
 * Encoded config blobs
 * (used only when ENCODED_CONFIG is defined)
 * ========================= */

static unsigned char enc_user_agent[] = {
    // "Mozilla/5.0 (X11; Linux x86_64) CSC840-Beacon/1.0"
    0x67,0x45,0x50,0x43,0x46,0x46,0x4b,0x05,
    0x1f,0x04,0x1a,0x0a,0x02,0x72,0x1b,0x1b,
    0x11,0x0a,0x66,0x43,0x44,0x5f,0x52,0x0a,
    0x52,0x12,0x1c,0x75,0x1c,0x1e,0x03,0x0a,
    0x69,0x79,0x69,0x12,0x1e,0x1a,0x07,0x68,
    0x4f,0x4b,0x49,0x45,0x44,0x05,0x1b,0x04,
    0x1a
};

static unsigned char enc_path[] = {
    // "/checkin"
    0x05,0x49,0x42,0x4f,0x49,0x41,0x43,0x44,0x00
};

static unsigned char enc_json[] = {
    // "{\"id\":\"CSC840-AGENT\",\"op\":\"ping\",\"ver\":\"1.0\"}"
    0x51,0x08,0x43,0x4e,0x08,0x10,0x08,0x69,
    0x79,0x69,0x12,0x1e,0x1a,0x07,0x6b,0x6d,
    0x6f,0x64,0x7e,0x08,0x06,0x08,0x45,0x5a,
    0x08,0x10,0x08,0x5a,0x43,0x44,0x4d,0x08,
    0x06,0x08,0x5c,0x4f,0x58,0x08,0x10,0x08,
    0x1b,0x04,0x1a,0x08,0x57
};

/* =========================
 * Plaintext config (used when ENCODED_CONFIG is NOT defined)
 * ========================= */
#ifndef ENCODED_CONFIG
static const char plain_user_agent[] =
    "Mozilla/5.0 (X11; Linux x86_64) CSC840-Beacon/1.0";
static const char plain_path[] = "/checkin";
static const char plain_json[] =
    "{\"id\":\"CSC840-AGENT\",\"op\":\"ping\",\"ver\":\"1.0\"}";
#endif

/* =========================
 * Config selection macros
 * ========================= */
#ifdef ENCODED_CONFIG
#define CFG_UA   ((const char *)enc_user_agent)
#define CFG_PATH ((const char *)enc_path)
#define CFG_JSON ((const char *)enc_json)
#else
#define CFG_UA   plain_user_agent
#define CFG_PATH plain_path
#define CFG_JSON plain_json
#endif

/* =========================
 * Utility functions
 * ========================= */

static void xor_decode(unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0x00) {
            break;
        }
        buf[i] ^= XOR_KEY;
    }
}

static int parse_task_and_apply(const char *task, int *base_sleep)
{
    // SAFE TASKS ONLY:
    //   SLEEP=<n>         : sleep once immediately (1..30)
    //   SET_INTERVAL=<n>  : update beacon interval (1..30)
    //   EXIT              : terminate cleanly

    if (!task || !base_sleep) {
        return 0;
    }

    while (*task == ' ' || *task == '\t' || *task == '\r' || *task == '\n') {
        task++;
    }

    if (strncmp(task, "EXIT", 4) == 0) {
        printf("[task] EXIT received. Terminating.\n");
        return 1;
    }

    if (strncmp(task, "SLEEP=", 6) == 0) {
        int s = atoi(task + 6);
        if (s > 0 && s <= MAX_SLEEP_S) {
            printf("[task] Sleeping once for %d seconds\n", s);
            sleep((unsigned)s);
        }
        return 0;
    }

    if (strncmp(task, "SET_INTERVAL=", 13) == 0) {
        int s = atoi(task + 13);
        if (s > 0 && s <= MAX_SLEEP_S) {
            *base_sleep = s;
            printf("[task] Updated base interval to %d seconds\n", *base_sleep);
        }
        return 0;
    }

    printf("[task] Unknown/ignored task: %s\n", task);
    return 0;
}

static int connect_localhost(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(C2_PORT);

    if (inet_pton(AF_INET, C2_IP, &addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed\n");
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* =========================
 * Main
 * ========================= */

int main(void)
{
#ifdef ENCODED_CONFIG
    xor_decode(enc_user_agent, sizeof(enc_user_agent));
    xor_decode(enc_path, sizeof(enc_path));
    xor_decode(enc_json, sizeof(enc_json));
#endif

    const char *ua   = CFG_UA;
    const char *path = CFG_PATH;
    const char *body = CFG_JSON;

    int base_sleep = 3;

    for (int i = 0; i < MAX_ITERS; i++) {
        printf("[*] Beacon iteration %d/%d\n", i + 1, MAX_ITERS);

        int fd = connect_localhost();
        if (fd >= 0) {
            char req[768];
            int len = snprintf(
                req, sizeof(req),
                "POST %s HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "User-Agent: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                path, ua, strlen(body), body
            );

            if (len > 0 && len < (int)sizeof(req)) {
                (void)send(fd, req, (size_t)len, 0);
            }

            char buf[512];
            ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';

                char *task = strstr(buf, "\r\n\r\n");
                task = (task != NULL) ? (task + 4) : buf;

                while (*task == ' ' || *task == '\t' ||
                       *task == '\r' || *task == '\n') {
                    task++;
                }

                printf("[<] Task body: '%s'\n", task);

                if (parse_task_and_apply(task, &base_sleep)) {
                    close(fd);
                    break;
                }
            }

            close(fd);
        }

        printf("[*] Sleeping %d seconds\n", base_sleep);
        sleep((unsigned)base_sleep);
    }

    puts("[*] Done.");
    return 0;
}
