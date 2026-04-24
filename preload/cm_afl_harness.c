#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "cm_afl_net_assets.h"
#include "cm_afl_native_assets.h"

typedef int (*main_fn_t)(int, char **, char **);
typedef int (*libc_start_main_fn_t)(
    main_fn_t,
    int,
    char **,
    void (*)(void),
    void (*)(void),
    void (*)(void),
    void *
);

static main_fn_t real_main_fn = NULL;
static libc_start_main_fn_t real_libc_start_main_fn = NULL;
static int verbose = 0;

enum {
    CM_OFF_CASE_0E_WRAPPER = 0x8F3C20,
    CM_OFF_CASE_DISPATCH_PARSER = 0x8F4E60,
    CM_OFF_COPY_DISPATCH_HELPER = 0x8F3D60,
    CM_OFF_MEMCPY_SINK = 0x8F431D,
    CM_OFF_VTBL_5E_OBJECT = 0x168A4C0,
    CM_OFF_SHARED_ACCESSINFO_GLOBAL = 0x20CBB90,
    CM_OFF_SHARED_ACCESSINFO_COUNTER = 0x20CDAF8,
    CM_OFF_SHARED_ACCESSINFO_PTHREAD_KEY = 0x1EBAF40,
};

struct cm_addrs {
    uintptr_t base;
    uintptr_t case_0e_wrapper;
    uintptr_t case_dispatch_parser;
    uintptr_t copy_dispatch_helper;
    uintptr_t memcpy_sink;
};

struct cm_live_blob {
    const struct cm_native_blob_asset *asset;
    unsigned char *data;
};

enum {
    CM_MID_RAX = 0,
    CM_MID_RBX,
    CM_MID_RCX,
    CM_MID_RDX,
    CM_MID_RSI,
    CM_MID_RDI,
    CM_MID_R8,
    CM_MID_R9,
    CM_MID_R10,
    CM_MID_R11,
    CM_MID_R12,
    CM_MID_R13,
    CM_MID_R14,
    CM_MID_R15,
    CM_MID_RBP,
    CM_MID_REG_COUNT,
};

struct cm_mode_runtime_patch {
    int active;
    uintptr_t global_ptr_slot;
    uintptr_t counter_slot;
    uint64_t old_global_ptr;
    uint32_t old_counter;
    unsigned char *synthetic_global;
    unsigned char *synthetic_subctx;
};

struct cm_net_sender_args {
    const struct cm_net_mode_asset *mode;
    const unsigned char *input;
    size_t input_len;
    int wait_ms;
    int io_timeout_ms;
};

static void log_line(const char *msg) {
    if (msg && *msg) {
        fputs(msg, stderr);
        fputc('\n', stderr);
    }
}

static void logf_if_verbose(const char *fmt, ...) {
    va_list ap;
    if (!verbose) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void die_errno(const char *msg) {
    fprintf(stderr, "[cm_afl_harness] %s: %s\n", msg, strerror(errno));
    _exit(2);
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    uintptr_t *base = (uintptr_t *)data;
    size_t i;
    (void)size;

    if (info->dlpi_name && info->dlpi_name[0] != '\0') {
        return 0;
    }
    for (i = 0; i < (size_t)info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X) != 0) {
            *base = (uintptr_t)info->dlpi_addr;
            return 1;
        }
    }
    return 0;
}

static uintptr_t find_exe_base(void) {
    uintptr_t base = 0;
    dl_iterate_phdr(phdr_cb, &base);
    return base;
}

static struct cm_addrs resolve_addrs(void) {
    struct cm_addrs addrs;
    memset(&addrs, 0, sizeof(addrs));
    addrs.base = find_exe_base();
    if (addrs.base == 0) {
        fprintf(stderr, "[cm_afl_harness] could not resolve executable base\n");
        _exit(2);
    }
    addrs.case_0e_wrapper = addrs.base + CM_OFF_CASE_0E_WRAPPER;
    addrs.case_dispatch_parser = addrs.base + CM_OFF_CASE_DISPATCH_PARSER;
    addrs.copy_dispatch_helper = addrs.base + CM_OFF_COPY_DISPATCH_HELPER;
    addrs.memcpy_sink = addrs.base + CM_OFF_MEMCPY_SINK;
    return addrs;
}

static unsigned char *read_input(const char *path, size_t *out_len) {
    struct stat st;
    FILE *fp;
    unsigned char *buf;
    size_t nread;

    *out_len = 0;
    if (!path || !*path) {
        return NULL;
    }
    if (stat(path, &st) != 0) {
        die_errno("stat(input)");
    }
    if (st.st_size < 0) {
        fprintf(stderr, "[cm_afl_harness] negative st_size for %s\n", path);
        _exit(2);
    }
    fp = fopen(path, "rb");
    if (!fp) {
        die_errno("fopen(input)");
    }
    buf = (unsigned char *)malloc((size_t)st.st_size ? (size_t)st.st_size : 1);
    if (!buf) {
        fprintf(stderr, "[cm_afl_harness] malloc failed for %s\n", path);
        fclose(fp);
        _exit(2);
    }
    nread = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    if (nread != (size_t)st.st_size) {
        fprintf(stderr, "[cm_afl_harness] short read on %s\n", path);
        free(buf);
        _exit(2);
    }
    *out_len = nread;
    return buf;
}

typedef uintptr_t (*case_wrapper_fn_t)(
    void *obj,
    void *input,
    uint32_t len,
    uintptr_t dummy,
    void *ctx,
    uintptr_t aux
);

typedef uintptr_t (*native_hot_fn_t)(
    uintptr_t a0,
    uintptr_t a1,
    uintptr_t a2,
    uintptr_t a3,
    uintptr_t a4,
    uintptr_t a5
);

static void *build_5e_object(const struct cm_addrs *addrs) {
    unsigned char *obj = (unsigned char *)calloc(1, 0xb8);
    uint64_t minus_one = UINT64_C(0xffffffffffffffff);
    uint32_t minus_one_32 = 0xffffffffU;

    if (!obj) {
        die_errno("calloc(0xb8)");
    }
    *(uintptr_t *)(obj + 0x00) = addrs->base + CM_OFF_VTBL_5E_OBJECT;
    memcpy(obj + 0x08, &minus_one, sizeof(minus_one));
    memcpy(obj + 0x1c, &minus_one_32, sizeof(minus_one_32));
    obj[0x29] = 0x5e;
    memset(obj + 0x60, 0, 0x50);
    return obj;
}

static void *build_fake_ctx(void *obj) {
    unsigned char *base = (unsigned char *)calloc(1, 0xc0);
    unsigned char *ctx;
    uint64_t q0 = UINT64_C(0x0000000200000000);
    void *tail = (unsigned char *)obj + 0xb0;

    if (!base) {
        die_errno("calloc(fake_ctx)");
    }
    ctx = base + 0x30;
    memcpy(ctx + 0x00, &q0, sizeof(q0));
    *(void **)(ctx + 0x68) = tail;
    *(void **)(ctx + 0x70) = tail;
    *(void **)(ctx + 0x78) = tail;
    return ctx;
}

static uint64_t read_u64(const unsigned char *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void write_u64(unsigned char *p, uint64_t v) {
    memcpy(p, &v, sizeof(v));
}

__attribute__((noreturn, naked)) static void cm_midblock_done(void) {
    __asm__ volatile(
        "xor %edi, %edi\n\t"
        "call _exit@PLT\n\t"
    );
}

__attribute__((noreturn, noinline)) static void cm_run_midblock_jump(const uint64_t *regs, void *rsp0) {
    __asm__ volatile(
        "mov %[rsp0], %%rsp\n\t"
        "mov %[regs], %%r10\n\t"
        "mov 0(%%r10), %%rax\n\t"
        "mov 8(%%r10), %%rbx\n\t"
        "mov 16(%%r10), %%rcx\n\t"
        "mov 24(%%r10), %%rdx\n\t"
        "mov 32(%%r10), %%rsi\n\t"
        "mov 40(%%r10), %%rdi\n\t"
        "mov 48(%%r10), %%r8\n\t"
        "mov 56(%%r10), %%r9\n\t"
        "mov 88(%%r10), %%r13\n\t"
        "mov 96(%%r10), %%r14\n\t"
        "mov 104(%%r10), %%r15\n\t"
        "mov 112(%%r10), %%rbp\n\t"
        "mov 80(%%r10), %%r12\n\t"
        "mov 72(%%r10), %%r11\n\t"
        "mov 64(%%r10), %%r10\n\t"
        "jmp *-8(%%rsp)\n\t"
        :
        : [regs] "r" (regs), [rsp0] "r" (rsp0)
        : "memory"
    );
    __builtin_unreachable();
}

static const struct cm_native_mode_asset *find_native_mode(const char *mode) {
    size_t i;
    if (!mode) {
        return NULL;
    }
    for (i = 0; i < CM_NATIVE_MODE_COUNT; i++) {
        const struct cm_native_mode_asset *m = cm_native_all_modes[i];
        if (strcmp(m->mode, mode) == 0) {
            return m;
        }
    }
    return NULL;
}

static const struct cm_net_mode_asset *find_net_mode(const char *mode) {
    size_t i;
    if (!mode) {
        return NULL;
    }
    for (i = 0; i < CM_NET_MODE_COUNT; i++) {
        const struct cm_net_mode_asset *m = cm_net_all_modes[i];
        if (strcmp(m->mode, mode) == 0) {
            return m;
        }
    }
    return NULL;
}

static uint32_t cm_magic_div_1009(uint32_t eax) {
    uint64_t rcx;
    eax = (uint32_t)((uint64_t)eax * 1000U);
    rcx = ((uint64_t)eax * UINT64_C(0x3ce4585)) >> 32;
    eax = (uint32_t)(eax - (uint32_t)rcx);
    eax >>= 1;
    eax = (uint32_t)(eax + (uint32_t)rcx);
    return eax >> 9;
}

static void cm_derive_session_key_iv(uint32_t t, unsigned char key[16], unsigned char iv[16]) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char le[4];
    uint32_t bucket = cm_magic_div_1009(t);

    le[0] = (unsigned char)(bucket & 0xffU);
    le[1] = (unsigned char)((bucket >> 8) & 0xffU);
    le[2] = (unsigned char)((bucket >> 16) & 0xffU);
    le[3] = (unsigned char)((bucket >> 24) & 0xffU);
    SHA1(le, sizeof(le), digest);
    memcpy(key, digest, 16);
    memcpy(iv, digest + 4, 16);
}

static void cm_cts_shuffle(unsigned char *buf, size_t len) {
    unsigned char tmp[16];
    if (!buf || len < 32) {
        return;
    }
    memcpy(tmp, buf + len - 16, 16);
    memmove(buf + len - 16, buf + len - 32, 16);
    memcpy(buf + len - 32, tmp, 16);
}

static int cm_aes_cbc_crypt(
    int encrypt,
    const unsigned char *in,
    size_t len,
    const unsigned char key[16],
    const unsigned char iv[16],
    unsigned char *out
) {
    EVP_CIPHER_CTX *ctx;
    int n0 = 0;
    int n1 = 0;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    if (encrypt) {
        ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
        ok = ok && EVP_CIPHER_CTX_set_padding(ctx, 0);
        ok = ok && EVP_EncryptUpdate(ctx, out, &n0, in, (int)len);
        ok = ok && EVP_EncryptFinal_ex(ctx, out + n0, &n1);
    } else {
        ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
        ok = ok && EVP_CIPHER_CTX_set_padding(ctx, 0);
        ok = ok && EVP_DecryptUpdate(ctx, out, &n0, in, (int)len);
        ok = ok && EVP_DecryptFinal_ex(ctx, out + n0, &n1);
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok || (size_t)(n0 + n1) != len) {
        return -1;
    }
    return 0;
}

static unsigned char *cm_build_mac_suffix(const unsigned char *data, size_t len, size_t *out_len) {
    unsigned char *full;
    size_t aligned = ((len + 16U) + 15U) & ~(size_t)15U;
    size_t pad_len;
    uint32_t crc;
    if (aligned < 32) {
        aligned = 32;
    }
    pad_len = aligned - len - 8;
    full = (unsigned char *)calloc(1, aligned);
    if (!full) {
        return NULL;
    }
    if (len) {
        memcpy(full, data, len);
    }
    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, data, (uInt)len);
    full[len + pad_len + 0] = (unsigned char)(len & 0xffU);
    full[len + pad_len + 1] = (unsigned char)((len >> 8) & 0xffU);
    full[len + pad_len + 2] = (unsigned char)((len >> 16) & 0xffU);
    full[len + pad_len + 3] = (unsigned char)((len >> 24) & 0xffU);
    full[len + pad_len + 4] = (unsigned char)(crc & 0xffU);
    full[len + pad_len + 5] = (unsigned char)((crc >> 8) & 0xffU);
    full[len + pad_len + 6] = (unsigned char)((crc >> 16) & 0xffU);
    full[len + pad_len + 7] = (unsigned char)((crc >> 24) & 0xffU);
    *out_len = aligned;
    return full;
}

static unsigned char *cm_encrypt_c2d_frame(
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint32_t t,
    size_t *wire_len
) {
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *full = NULL;
    unsigned char *ct = NULL;
    unsigned char *wire = NULL;
    size_t full_len = 0;
    size_t body_len;

    full = cm_build_mac_suffix(plaintext, plaintext_len, &full_len);
    if (!full) {
        return NULL;
    }
    ct = (unsigned char *)malloc(full_len);
    if (!ct) {
        free(full);
        return NULL;
    }
    cm_derive_session_key_iv(t, key, iv);
    if (cm_aes_cbc_crypt(1, full, full_len, key, iv, ct) != 0) {
        free(ct);
        free(full);
        return NULL;
    }
    cm_cts_shuffle(ct, full_len);
    body_len = 1 + full_len;
    wire = (unsigned char *)malloc(16 + body_len);
    if (!wire) {
        free(ct);
        free(full);
        return NULL;
    }
    memcpy(wire, "samc", 4);
    wire[4] = (unsigned char)(body_len & 0xffU);
    wire[5] = (unsigned char)((body_len >> 8) & 0xffU);
    wire[6] = (unsigned char)((body_len >> 16) & 0xffU);
    wire[7] = (unsigned char)((body_len >> 24) & 0xffU);
    wire[8] = 0x11;
    wire[9] = 0x00;
    wire[10] = 0x01;
    wire[11] = 0x00;
    memset(wire + 12, 0, 4);
    wire[16] = 0xa0;
    memcpy(wire + 17, ct, full_len);
    *wire_len = 16 + body_len;
    free(ct);
    free(full);
    return wire;
}

static unsigned char *cm_try_decrypt_d2c_body(
    const unsigned char *body,
    size_t body_len,
    uint32_t t,
    size_t *plaintext_len
) {
    int dt;
    if (!body || body_len < 32 || (body_len % 16) != 0) {
        return NULL;
    }
    for (dt = -30; dt <= 30; dt++) {
        unsigned char key[16];
        unsigned char iv[16];
        unsigned char *tmp;
        uint32_t length;
        uint32_t crc_expect;
        uint32_t crc_actual;

        tmp = (unsigned char *)malloc(body_len);
        if (!tmp) {
            return NULL;
        }
        memcpy(tmp, body, body_len);
        cm_cts_shuffle(tmp, body_len);
        cm_derive_session_key_iv((uint32_t)((int64_t)t + dt), key, iv);
        if (cm_aes_cbc_crypt(0, tmp, body_len, key, iv, tmp) != 0) {
            free(tmp);
            continue;
        }
        length = (uint32_t)tmp[body_len - 8]
            | ((uint32_t)tmp[body_len - 7] << 8)
            | ((uint32_t)tmp[body_len - 6] << 16)
            | ((uint32_t)tmp[body_len - 5] << 24);
        crc_expect = (uint32_t)tmp[body_len - 4]
            | ((uint32_t)tmp[body_len - 3] << 8)
            | ((uint32_t)tmp[body_len - 2] << 16)
            | ((uint32_t)tmp[body_len - 1] << 24);
        if (length <= body_len - 8) {
            crc_actual = crc32(0L, Z_NULL, 0);
            crc_actual = crc32(crc_actual, tmp, length);
            if (crc_actual == crc_expect) {
                unsigned char *pt = (unsigned char *)malloc(length ? length : 1);
                if (!pt) {
                    free(tmp);
                    return NULL;
                }
                if (length) {
                    memcpy(pt, tmp, length);
                }
                *plaintext_len = length;
                free(tmp);
                return pt;
            }
        }
        free(tmp);
    }
    return NULL;
}

static int cm_send_all(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static unsigned char *cm_recv_exact(int fd, size_t want, int timeout_ms, size_t *got_len) {
    unsigned char *buf = (unsigned char *)malloc(want ? want : 1);
    size_t off = 0;
    if (!buf) {
        return NULL;
    }
    while (off < want) {
        struct pollfd pfd;
        int rc;
        ssize_t n;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) {
            break;
        }
        n = recv(fd, buf + off, want - off, 0);
        if (n <= 0) {
            break;
        }
        off += (size_t)n;
    }
    *got_len = off;
    if (off != want) {
        free(buf);
        return NULL;
    }
    return buf;
}

static unsigned char *cm_recv_one_wire_frame(int fd, int timeout_ms, size_t *wire_len) {
    unsigned char *hdr;
    unsigned char *wire;
    size_t got = 0;
    uint32_t body_len;
    hdr = cm_recv_exact(fd, 16, timeout_ms, &got);
    if (!hdr || got != 16 || memcmp(hdr, "samc", 4) != 0) {
        free(hdr);
        return NULL;
    }
    body_len = (uint32_t)hdr[4]
        | ((uint32_t)hdr[5] << 8)
        | ((uint32_t)hdr[6] << 16)
        | ((uint32_t)hdr[7] << 24);
    if (body_len > (1U << 20)) {
        free(hdr);
        return NULL;
    }
    wire = (unsigned char *)malloc(16 + body_len);
    if (!wire) {
        free(hdr);
        return NULL;
    }
    memcpy(wire, hdr, 16);
    free(hdr);
    if (body_len != 0) {
        unsigned char *body = cm_recv_exact(fd, body_len, timeout_ms, &got);
        if (!body || got != body_len) {
            free(body);
            free(wire);
            return NULL;
        }
        memcpy(wire + 16, body, body_len);
        free(body);
    }
    *wire_len = 16 + body_len;
    return wire;
}

static int cm_wait_for_port_22350(int wait_ms) {
    struct timespec start;
    int elapsed = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed < wait_ms) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        if (fd < 0) {
            break;
        }
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(22350);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            return fd;
        }
        close(fd);
        usleep(50 * 1000);
        {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            elapsed = (int)((now.tv_sec - start.tv_sec) * 1000
                + (now.tv_nsec - start.tv_nsec) / 1000000);
        }
    }
    return -1;
}

static void cm_patch_token(
    unsigned char *frame,
    size_t frame_len,
    const struct cm_net_mode_asset *mode,
    size_t frame_index,
    const unsigned char *token
) {
    if (!frame || !token || mode->token_frame < 0 || (size_t)mode->token_frame != frame_index) {
        return;
    }
    if (mode->token_offset + mode->token_len <= frame_len) {
        memcpy(frame + mode->token_offset, token, mode->token_len);
    }
}

static void cm_patch_sid(
    unsigned char *frame,
    size_t frame_len,
    const struct cm_net_mode_asset *mode,
    size_t frame_index,
    unsigned char **replies,
    size_t *reply_lens
) {
    size_t i;
    for (i = 0; i < mode->sid_patch_count; i++) {
        const struct cm_net_sid_patch *patch = &mode->sid_patches[i];
        if (patch->frame_index != frame_index) {
            continue;
        }
        if (!replies[patch->reply_index] || reply_lens[patch->reply_index] < 8) {
            continue;
        }
        if (patch->offset + 4 <= frame_len) {
            memcpy(frame + patch->offset, replies[patch->reply_index] + 4, 4);
        }
    }
}

static void cm_free_reply_cache(unsigned char **replies) {
    size_t i;
    for (i = 0; i < 16; i++) {
        free(replies[i]);
    }
}

static void *cm_net_sender_thread(void *opaque) {
    struct cm_net_sender_args *args = (struct cm_net_sender_args *)opaque;
    int fd;
    unsigned char token[8];
    unsigned char *replies[16];
    size_t reply_lens[16];
    size_t reply_count = 0;
    size_t i;

    memset(replies, 0, sizeof(replies));
    memset(reply_lens, 0, sizeof(reply_lens));
    memset(token, 0, sizeof(token));
    if (args->mode->token_len > sizeof(token)) {
        log_line("[cm_afl_harness] token_len too large");
        _exit(2);
    }
    if (args->mode->token_len && RAND_bytes(token, (int)args->mode->token_len) != 1) {
        log_line("[cm_afl_harness] RAND_bytes(token) failed");
        _exit(2);
    }

    fd = cm_wait_for_port_22350(args->wait_ms);
    if (fd < 0) {
        log_line("[cm_afl_harness] timeout waiting for :22350");
        _exit(2);
    }
    logf_if_verbose("[cm_afl_harness] net sender connected mode=%s frames=%zu\n",
        args->mode->mode, args->mode->frame_count);

    for (i = 0; i < args->mode->frame_count; i++) {
        const struct cm_net_frame_asset *asset = &args->mode->frames[i];
        const unsigned char *src = asset->data;
        size_t frame_len = asset->len;
        unsigned char *frame;
        unsigned char *wire;
        size_t wire_len = 0;
        size_t wire_reply_len = 0;
        uint32_t now_t;
        unsigned char *wire_reply;
        unsigned char *reply_pt;
        size_t reply_pt_len = 0;

        if (i == args->mode->mutate_index && args->input && args->input_len) {
            src = args->input;
            frame_len = args->input_len;
        }
        frame = (unsigned char *)malloc(frame_len ? frame_len : 1);
        if (!frame) {
            close(fd);
            cm_free_reply_cache(replies);
            die_errno("malloc(net_frame)");
        }
        if (frame_len) {
            memcpy(frame, src, frame_len);
        }
        cm_patch_token(frame, frame_len, args->mode, i, token);
        cm_patch_sid(frame, frame_len, args->mode, i, replies, reply_lens);
        now_t = (uint32_t)time(NULL);
        wire = cm_encrypt_c2d_frame(frame, frame_len, now_t, &wire_len);
        free(frame);
        if (!wire) {
            close(fd);
            cm_free_reply_cache(replies);
            log_line("[cm_afl_harness] encrypt_c2d_frame failed");
            _exit(2);
        }
        if (cm_send_all(fd, wire, wire_len) != 0) {
            free(wire);
            close(fd);
            cm_free_reply_cache(replies);
            _exit(0);
        }
        logf_if_verbose("[cm_afl_harness] net frame[%zu] sent len=%zu\n", i, frame_len);
        free(wire);
        wire_reply = cm_recv_one_wire_frame(fd, args->io_timeout_ms, &wire_reply_len);
        if (!wire_reply) {
            close(fd);
            cm_free_reply_cache(replies);
            _exit(0);
        }
        reply_pt = cm_try_decrypt_d2c_body(wire_reply + 16, wire_reply_len - 16, now_t, &reply_pt_len);
        free(wire_reply);
        if (!reply_pt) {
            close(fd);
            cm_free_reply_cache(replies);
            _exit(0);
        }
        logf_if_verbose("[cm_afl_harness] net reply[%zu] decrypted len=%zu\n", reply_count, reply_pt_len);
        if (reply_count < 16) {
            replies[reply_count] = reply_pt;
            reply_lens[reply_count] = reply_pt_len;
            reply_count++;
        } else {
            free(reply_pt);
        }
    }

    usleep(100 * 1000);
    close(fd);
    cm_free_reply_cache(replies);
    _exit(0);
}

static void free_live_blobs(struct cm_live_blob *blobs, size_t count) {
    size_t i;
    if (!blobs) {
        return;
    }
    for (i = 0; i < count; i++) {
        free(blobs[i].data);
    }
    free(blobs);
}

static struct cm_live_blob *clone_live_blobs(const struct cm_native_mode_asset *mode) {
    size_t i;
    struct cm_live_blob *blobs = (struct cm_live_blob *)calloc(mode->blob_count, sizeof(*blobs));
    if (!blobs) {
        die_errno("calloc(live_blobs)");
    }
    for (i = 0; i < mode->blob_count; i++) {
        const struct cm_native_blob_asset *asset = &mode->blobs[i];
        blobs[i].asset = asset;
        blobs[i].data = (unsigned char *)malloc(asset->size);
        if (!blobs[i].data) {
            free_live_blobs(blobs, mode->blob_count);
            die_errno("malloc(blob)");
        }
        memcpy(blobs[i].data, asset->data, asset->size);
    }
    return blobs;
}

static uint64_t maybe_reloc_qword(
    uint64_t q,
    const struct cm_native_mode_asset *mode,
    const struct cm_live_blob *blobs,
    uintptr_t current_base
) {
    size_t i;
    if (q >= mode->orig_base && q < mode->orig_base + 0x3000000ULL) {
        return current_base + (uintptr_t)(q - mode->orig_base);
    }
    for (i = 0; i < mode->blob_count; i++) {
        uint64_t start = mode->blobs[i].orig_addr;
        uint64_t end = start + mode->blobs[i].size;
        if (q >= start && q < end) {
            return (uint64_t)((uintptr_t)blobs[i].data + (uintptr_t)(q - start));
        }
    }
    return q;
}

static void patch_live_blobs(
    const struct cm_native_mode_asset *mode,
    struct cm_live_blob *blobs,
    uintptr_t current_base
) {
    size_t i, off;
    for (i = 0; i < mode->blob_count; i++) {
        for (off = 0; off + 8 <= blobs[i].asset->size; off += 8) {
            uint64_t q = read_u64(blobs[i].data + off);
            uint64_t patched = maybe_reloc_qword(q, mode, blobs, current_base);
            if (patched != q) {
                write_u64(blobs[i].data + off, patched);
            }
        }
    }
}

static unsigned char *clone_stack_snapshot(const struct cm_native_mode_asset *mode) {
    unsigned char *stack;
    if (!mode->stack_data || mode->stack_size == 0) {
        return NULL;
    }
    stack = (unsigned char *)malloc(mode->stack_size);
    if (!stack) {
        die_errno("malloc(stack_snapshot)");
    }
    memcpy(stack, mode->stack_data, mode->stack_size);
    return stack;
}

static void patch_qwords_region(
    unsigned char *data,
    size_t size,
    const struct cm_native_mode_asset *mode,
    const struct cm_live_blob *blobs,
    uintptr_t current_base
) {
    size_t off;
    for (off = 0; off + 8 <= size; off += 8) {
        uint64_t q = read_u64(data + off);
        uint64_t patched = maybe_reloc_qword(q, mode, blobs, current_base);
        if (patched != q) {
            write_u64(data + off, patched);
        }
    }
}

static void mutate_region(unsigned char *data, size_t size, size_t off, size_t cap, const unsigned char *input, size_t input_len) {
    size_t n;
    if (off >= size || cap == 0) {
        return;
    }
    if (off + cap > size) {
        cap = size - off;
    }
    memset(data + off, 0, cap);
    n = input_len < cap ? input_len : cap;
    if (n) {
        memcpy(data + off, input, n);
    }
}

static void mutate_two_strings(struct cm_live_blob *blobs, const unsigned char *input, size_t input_len, uintptr_t *regs) {
    unsigned char *a = blobs[0].data;
    unsigned char *b = blobs[1].data;
    size_t a_cap = 0x3f;
    size_t b_cap = 0x3f;
    size_t split = input_len / 2;
    size_t a_len = split;
    size_t b_len = input_len - split;

    if (a_len > a_cap) {
        a_len = a_cap;
    }
    if (b_len > b_cap) {
        b_len = b_cap;
    }
    memset(a, 0, a_cap + 1);
    memset(b, 0, b_cap + 1);
    if (a_len) {
        memcpy(a, input, a_len);
    }
    if (b_len) {
        memcpy(b, input + split, b_len);
    }
    regs[3] = (uintptr_t)(a_len ? a_len : 1);
}

static void mutate_len_region(
    const struct cm_native_mode_asset *mode,
    struct cm_live_blob *blobs,
    const unsigned char *input,
    size_t input_len,
    uintptr_t *regs
) {
    unsigned char *blob = blobs[mode->mutate_blob_index].data;
    uint64_t n = (uint64_t)(input_len ? (input_len < mode->mutate_capacity ? input_len : mode->mutate_capacity) : 1);
    mutate_region(blob, blobs[mode->mutate_blob_index].asset->size, mode->mutate_offset, mode->mutate_capacity, input, input_len);
    if (mode->len_field1 != (size_t)-1 && mode->len_field1 + 8 <= blobs[mode->mutate_blob_index].asset->size) {
        write_u64(blob + mode->len_field1, n);
    }
    if (mode->len_field2 != (size_t)-1 && mode->len_field2 + 8 <= blobs[mode->mutate_blob_index].asset->size) {
        write_u64(blob + mode->len_field2, n);
    }
    regs[2] = (uintptr_t)n;
}

static void mutate_qword_slots(
    const struct cm_native_mode_asset *mode,
    struct cm_live_blob *blobs,
    const unsigned char *input,
    size_t input_len
) {
    unsigned char *blob = blobs[mode->mutate_blob_index].data;
    size_t blob_size = blobs[mode->mutate_blob_index].asset->size;
    size_t slot_index;

    for (slot_index = 0; slot_index < mode->slot_count; slot_index++) {
        size_t off = mode->slot_offsets[slot_index];
        size_t in_off = slot_index * sizeof(uint64_t);
        uint64_t patched = 0;
        size_t chunk = 0;

        if (off + sizeof(uint64_t) > blob_size || in_off >= input_len) {
            continue;
        }
        chunk = input_len - in_off;
        if (chunk > sizeof(uint64_t)) {
            chunk = sizeof(uint64_t);
        }
        memcpy(&patched, input + in_off, chunk);
        write_u64(blob + off, patched);
    }
}

static void apply_native_input(
    const struct cm_native_mode_asset *mode,
    struct cm_live_blob *blobs,
    const unsigned char *input,
    size_t input_len,
    uintptr_t *regs
) {
    switch (mode->mutate_kind) {
    case CM_MUTATE_TWO_STRINGS:
        mutate_two_strings(blobs, input, input_len, regs);
        break;
    case CM_MUTATE_RCX_PAYLOAD:
        mutate_len_region(mode, blobs, input, input_len, regs);
        break;
    case CM_MUTATE_QWORD_SLOTS:
        mutate_qword_slots(mode, blobs, input, input_len);
        break;
    case CM_MUTATE_REGION:
    default:
        mutate_region(
            blobs[mode->mutate_blob_index].data,
            blobs[mode->mutate_blob_index].asset->size,
            mode->mutate_offset,
            mode->mutate_capacity,
            input,
            input_len
        );
        break;
    }
}

static void prepare_mode_runtime(
    const struct cm_addrs *addrs,
    const struct cm_native_mode_asset *mode,
    struct cm_mode_runtime_patch *patch
) {
    memset(patch, 0, sizeof(*patch));
    if (strcmp(mode->mode, "7068d0_shared") != 0) {
        return;
    }

    patch->synthetic_global = (unsigned char *)calloc(1, 0x480);
    patch->synthetic_subctx = (unsigned char *)calloc(1, 0x80);
    if (!patch->synthetic_global || !patch->synthetic_subctx) {
        die_errno("calloc(shared_accessinfo)");
    }

    patch->active = 1;
    patch->global_ptr_slot = addrs->base + CM_OFF_SHARED_ACCESSINFO_GLOBAL;
    patch->counter_slot = addrs->base + CM_OFF_SHARED_ACCESSINFO_COUNTER;
    patch->old_global_ptr = *(uint64_t *)patch->global_ptr_slot;
    patch->old_counter = *(uint32_t *)patch->counter_slot;

    /* Minimal state for 0x706110/0x706120 and the later r12 walk. */
    patch->synthetic_global[0x474] = 0;
    *(uintptr_t *)(patch->synthetic_global + 0xe8) = (uintptr_t)patch->synthetic_subctx;
    *(uint64_t *)(patch->synthetic_subctx + 0x58) = 0;

    *(uintptr_t *)patch->global_ptr_slot = (uintptr_t)patch->synthetic_global;
    *(uint32_t *)patch->counter_slot = 0;
}

static void restore_mode_runtime(struct cm_mode_runtime_patch *patch) {
    if (!patch->active) {
        return;
    }
    *(uint64_t *)patch->global_ptr_slot = patch->old_global_ptr;
    *(uint32_t *)patch->counter_slot = patch->old_counter;
    free(patch->synthetic_subctx);
    free(patch->synthetic_global);
}

static int run_native_mode(
    const struct cm_addrs *addrs,
    const struct cm_native_mode_asset *mode,
    const unsigned char *input,
    size_t input_len
) {
    struct cm_live_blob *blobs;
    struct cm_mode_runtime_patch patch;
    uintptr_t regs[6];
    size_t i;
    native_hot_fn_t fn = (native_hot_fn_t)(addrs->base + mode->func_off);

    blobs = clone_live_blobs(mode);
    patch_live_blobs(mode, blobs, addrs->base);
    memcpy(regs, mode->regs, sizeof(regs));
    for (i = 0; i < 6; i++) {
        regs[i] = (uintptr_t)maybe_reloc_qword((uint64_t)regs[i], mode, blobs, addrs->base);
    }
    for (i = 0; i < mode->blob_count; i++) {
        if (mode->blobs[i].arg_index >= 0) {
            regs[mode->blobs[i].arg_index] = (uintptr_t)blobs[i].data;
        }
    }
    apply_native_input(mode, blobs, input, input_len, regs);
    prepare_mode_runtime(addrs, mode, &patch);
    logf_if_verbose(
        "[cm_afl_harness] native mode=%s fn=%p a0=%p a1=%p a2=%p a3=%p a4=%p a5=%p len=%zu\n",
        mode->mode,
        (void *)fn,
        (void *)regs[0],
        (void *)regs[1],
        (void *)regs[2],
        (void *)regs[3],
        (void *)regs[4],
        (void *)regs[5],
        input_len
    );
    fn(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]);
    restore_mode_runtime(&patch);
    free_live_blobs(blobs, mode->blob_count);
    return 0;
}

static int run_native_midblock_mode(
    const struct cm_addrs *addrs,
    const struct cm_native_mode_asset *mode,
    const unsigned char *input,
    size_t input_len
) {
    struct cm_live_blob *blobs;
    unsigned char *stack_raw;
    unsigned char *stack;
    uint64_t regs[CM_MID_REG_COUNT];
    uintptr_t target;
    size_t i;

    blobs = clone_live_blobs(mode);
    patch_live_blobs(mode, blobs, addrs->base);
    stack_raw = clone_stack_snapshot(mode);
    if (!stack_raw) {
        free_live_blobs(blobs, mode->blob_count);
        log_line("[cm_afl_harness] midblock mode missing stack snapshot");
        _exit(2);
    }
    stack = (unsigned char *)malloc(mode->stack_size + 0x20);
    if (!stack) {
        free(stack_raw);
        free_live_blobs(blobs, mode->blob_count);
        die_errno("malloc(midblock_stack)");
    }
    memset(stack, 0, mode->stack_size + 0x20);
    stack += 0x20;
    memcpy(stack, stack_raw, mode->stack_size);
    free(stack_raw);

    memcpy(regs, mode->full_regs, sizeof(regs));
    for (i = 0; i < CM_MID_REG_COUNT; i++) {
        regs[i] = maybe_reloc_qword(regs[i], mode, blobs, addrs->base);
    }
    for (i = 0; i < mode->blob_count; i++) {
        if (mode->blobs[i].arg_index >= 0) {
            regs[mode->blobs[i].arg_index] = (uintptr_t)blobs[i].data;
        }
    }
    apply_native_input(mode, blobs, input, input_len, regs);
    patch_qwords_region(stack, mode->stack_size, mode, blobs, addrs->base);
    write_u64(stack, (uint64_t)(uintptr_t)cm_midblock_done);
    target = addrs->base + mode->func_off;
    write_u64(stack - 8, target);

    logf_if_verbose(
        "[cm_afl_harness] native midblock mode=%s pc=%p rsp=%p len=%zu\n",
        mode->mode,
        (void *)target,
        (void *)stack,
        input_len
    );
    cm_run_midblock_jump(regs, stack);
}

static int harness_main(int argc, char **argv, char **envp) {
    const char *mode = getenv("CM_AFL_HARNESS_MODE");
    const char *inner_daemon = getenv("CM_AFL_INNER_DAEMON");
    const struct cm_native_mode_asset *native_mode = NULL;
    const struct cm_net_mode_asset *net_mode = NULL;
    const char *input_path = NULL;
    struct cm_addrs addrs;
    unsigned char *input = NULL;
    size_t input_len = 0;

    (void)envp;
    verbose = getenv("CM_AFL_VERBOSE") != NULL;

    if (inner_daemon && real_main_fn) {
        return real_main_fn(argc, argv, envp);
    }

    if (mode && strcmp(mode, "bypass") == 0) {
        if (!real_main_fn) {
            fprintf(stderr, "[cm_afl_harness] bypass requested but real main missing\n");
            return 2;
        }
        return real_main_fn(argc, argv, envp);
    }

    addrs = resolve_addrs();
    native_mode = find_native_mode(mode);
    net_mode = find_net_mode(mode);
    logf_if_verbose(
        "[cm_afl_harness] mode=%s base=%p parser=%p helper=%p memcpy_sink=%p\n",
        mode ? mode : "probe",
        (void *)addrs.base,
        (void *)addrs.case_dispatch_parser,
        (void *)addrs.copy_dispatch_helper,
        (void *)addrs.memcpy_sink
    );

    if (argc > 1 && argv[1] && argv[1][0] != '-') {
        input_path = argv[1];
    } else {
        input_path = getenv("CM_AFL_INPUT");
    }
    if (input_path && *input_path) {
        input = read_input(input_path, &input_len);
        logf_if_verbose(
            "[cm_afl_harness] input=%s len=%zu first_opcode=%s0x%02x\n",
            input_path,
            input_len,
            input_len ? "" : "n/a:",
            input_len ? input[0] : 0
        );
    } else {
        if (verbose) {
            log_line("[cm_afl_harness] no input provided");
        }
    }

    if (net_mode) {
        static char *daemon_argv[] = { (char *)"CodeMeterLin", (char *)"-f", NULL };
        struct cm_net_sender_args sender_args;
        pthread_t tid;
        int rc;

        if (!real_main_fn) {
            log_line("[cm_afl_harness] net mode requested but real main missing");
            return 2;
        }
        sender_args.mode = net_mode;
        sender_args.input = input;
        sender_args.input_len = input_len;
        sender_args.wait_ms = 10000;
        sender_args.io_timeout_ms = 1500;
        setenv("CM_AFL_INNER_DAEMON", "1", 1);
        rc = pthread_create(&tid, NULL, cm_net_sender_thread, &sender_args);
        if (rc != 0) {
            errno = rc;
            die_errno("pthread_create(net_sender)");
        }
        pthread_detach(tid);
        logf_if_verbose("[cm_afl_harness] net mode=%s daemon main starting\n", net_mode->mode);
        return real_main_fn(2, daemon_argv, envp);
    }

    if (mode && strcmp(mode, "call_stub") == 0) {
        case_wrapper_fn_t wrapper;
        void *obj;
        void *ctx;
        uintptr_t ret;

        if (!input || input_len == 0) {
            log_line("[cm_afl_harness] call_stub needs a non-empty input");
            return 2;
        }
        wrapper = (case_wrapper_fn_t)addrs.case_0e_wrapper;
        obj = build_5e_object(&addrs);
        ctx = build_fake_ctx(obj);
        logf_if_verbose(
            "[cm_afl_harness] call_stub obj=%p ctx=%p ctx_base=%p obj_tail=%p len=%zu\n",
            obj,
            ctx,
            (unsigned char *)ctx - 0x30,
            (unsigned char *)obj + 0xb0,
            input_len
        );
        ret = wrapper(obj, input, (uint32_t)input_len, 0, ctx, 0xb8);
        logf_if_verbose("[cm_afl_harness] call_stub ret=%p\n", (void *)ret);
        /* The live parser path mutates ownership of this state. Do not free it here. */
        input = NULL;
        _exit(0);
    }
    if (native_mode) {
        if (native_mode->use_midblock) {
            run_native_midblock_mode(&addrs, native_mode, input, input_len);
        }
        run_native_mode(&addrs, native_mode, input, input_len);
        free(input);
        _exit(0);
    }
    free(input);
    _exit(0);
}

int __libc_start_main(
    main_fn_t main,
    int argc,
    char **ubp_av,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end
) {
    real_main_fn = main;
    if (!real_libc_start_main_fn) {
        real_libc_start_main_fn = (libc_start_main_fn_t)dlsym(RTLD_NEXT, "__libc_start_main");
        if (!real_libc_start_main_fn) {
            fprintf(stderr, "[cm_afl_harness] dlsym(__libc_start_main) failed\n");
            _exit(2);
        }
    }
    return real_libc_start_main_fn(harness_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
