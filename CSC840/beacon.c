// beacon.c - Safe simulated HTTP beacon for CSC840 Final Project
// Harmless by design: localhost-only, no persistence, no exec, no exfil.

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define XOR_KEY     0x2A
#define C2_IP       "127.0.0.1"
#define C2_PORT     8080
#define MAX_ITERS   5
#define MAX_SLEEP_S 30

// XOR-"encrypted" config blobs (decoded at runtime)
// NOTE: These values are pre-XORed with 0x2A.
// You can regenerate them later with a helper if you want.

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

static void xor_decode(unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0x00) break;
        buf[i] ^= XOR_KEY;
    }
} // end xor_decode

static void parse_task_and_apply(const char *task)
{
    // Safe "tasking": only supports SLEEP=<1..30>
    if (!task) return;

    const char *prefix = "SLEEP=";
    if (strncmp(task, prefix, strlen(prefix)) == 0) {
        int s = atoi(task + (int)strlen(prefix));
        if (s > 0 && s <= MAX_SLEEP_S) {
            printf("[task] Applying sleep=%d seconds\n", s);
            sleep((unsigned)s);
        }
    }
} // end parse_task_and_apply

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
    addr.sin_port = htons(C2_PORT);

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
} // end connect_localhost

int main(void)
{
    // Decode "config" at runtime (classic RE artifact)
    xor_decode(enc_user_agent, sizeof(enc_user_agent));
    xor_decode(enc_path, sizeof(enc_path));
    xor_decode(enc_json, sizeof(enc_json));

    const char *ua   = (const char *)enc_user_agent;
    const char *path = (const char *)enc_path;
    const char *body = (const char *)enc_json;

    int base_sleep = 3;

    for (int i = 0; i < MAX_ITERS; i++) {
        printf("[*] Beacon iteration %d/%d\n", i + 1, MAX_ITERS);

        int fd = connect_localhost();
        if (fd >= 0) {
            char req[768];
            int len = snprintf(req, sizeof(req),
                "POST %s HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "User-Agent: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                path, ua, strlen(body), body);

            if (len > 0 && len < (int)sizeof(req)) {
                (void)send(fd, req, (size_t)len, 0);
            }

            // Optional response for demo: if listener replies "SLEEP=5" we apply it.
            char buf[128];
            ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                printf("[<] Received: %s\n", buf);
                parse_task_and_apply(buf);
            }

            close(fd);
        }

        printf("[*] Sleeping %d seconds\n", base_sleep);
        sleep((unsigned)base_sleep);
    }

    puts("[*] Done.");
    return 0;
} // end main
