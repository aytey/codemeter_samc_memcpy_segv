#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

static int run_native_mode(
    const struct cm_addrs *addrs,
    const struct cm_native_mode_asset *mode,
    const unsigned char *input,
    size_t input_len
) {
    struct cm_live_blob *blobs;
    uintptr_t regs[6];
    size_t i;
    native_hot_fn_t fn = (native_hot_fn_t)(addrs->base + mode->func_off);

    blobs = clone_live_blobs(mode);
    patch_live_blobs(mode, blobs, addrs->base);
    memcpy(regs, mode->regs, sizeof(regs));
    for (i = 0; i < mode->blob_count; i++) {
        regs[mode->blobs[i].arg_index] = (uintptr_t)blobs[i].data;
    }
    apply_native_input(mode, blobs, input, input_len, regs);
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
    free_live_blobs(blobs, mode->blob_count);
    return 0;
}

static int harness_main(int argc, char **argv, char **envp) {
    const char *mode = getenv("CM_AFL_HARNESS_MODE");
    const struct cm_native_mode_asset *native_mode = NULL;
    const char *input_path = NULL;
    struct cm_addrs addrs;
    unsigned char *input = NULL;
    size_t input_len = 0;

    (void)envp;
    verbose = getenv("CM_AFL_VERBOSE") != NULL;

    if (mode && strcmp(mode, "bypass") == 0) {
        if (!real_main_fn) {
            fprintf(stderr, "[cm_afl_harness] bypass requested but real main missing\n");
            return 2;
        }
        return real_main_fn(argc, argv, envp);
    }

    addrs = resolve_addrs();
    native_mode = find_native_mode(mode);
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
