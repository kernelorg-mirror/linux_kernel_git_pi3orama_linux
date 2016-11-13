#ifndef PERF_UTIL_CLANG_C_H
#define PERF_UTIL_CLANG_C_H

#include <stddef.h>	/* for size_t */
#include <util-cxx.h>	/* for __maybe_unused */

#ifdef __cplusplus
extern "C" {
#endif

typedef void *jitted_funcs_map_t;
#ifdef HAVE_LIBCLANGLLVM_SUPPORT
extern void perf_clang__init(void);
extern void perf_clang__cleanup(void);

extern int test__clang_to_IR(void);
extern int test__clang_to_obj(void);
extern int test__clang_jit(void);

extern void test__clang_callback(int x);

extern int perf_clang__compile_bpf(const char *filename,
				   void **p_obj_buf,
				   size_t *p_obj_buf_sz,
				   jitted_funcs_map_t *p_funcs_map,
				   void **p_map_base);

extern int
perf_clang__hook_jitted_func(jitted_funcs_map_t map, void *ctx, bool is_err);
#else


static inline void perf_clang__init(void) { }
static inline void perf_clang__cleanup(void) { }

static inline int test__clang_to_IR(void) { return -1; }
static inline int test__clang_to_obj(void) { return -1;}
static inline int test__clang_jit(void) { return -1;}

static inline int
perf_clang__compile_bpf(const char *filename __maybe_unused,
			void **p_obj_buf __maybe_unused,
			size_t *p_obj_buf_sz __maybe_unused,
			jitted_funcs_map_t *p_funcs_map __maybe_unused,
			void **p_map_base __maybe_unused)
{
	return -ENOTSUP;
}

static inline int
perf_clang__hook_jitted_func(jitted_funcs_map_t map __maybe_unused,
			     void *ctx __maybe_unused,
			     bool is_err __maybe_unused)
{
	return -ENOTSUP;
}

#endif

#ifdef __cplusplus
}
#endif
#endif
