#ifndef PERF_TEST_LLVM_H
#define PERF_TEST_LLVM_H

#include <stddef.h> /* for size_t */

struct test_llvm__bpf_result {
	size_t size;
	char object[];
};

extern struct test_llvm__bpf_result *p_test_llvm__bpf_result;
extern const char test_llvm__bpf_prog[];
void test_llvm__fetch_bpf_obj(void **p_obj_buf, size_t *p_obj_buf_sz);

#endif
