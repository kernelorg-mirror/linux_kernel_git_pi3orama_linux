#ifndef PERF_TEST_LLVM_H
#define PERF_TEST_LLVM_H

#include <stddef.h> /* for size_t */

struct test_llvm__bpf_result {
	size_t size;
	char object[];
};

extern const char test_llvm__bpf_prog[];
extern const char test_llvm__bpf_test_kbuild_prog[];
extern const char test_llvm__bpf_test_prologue_prog[];

enum test_llvm__testcase {
	LLVM_TESTCASE_BASE,
	LLVM_TESTCASE_KBUILD,
	/*
	 * We must put LLVM_TESTCASE_BPF_PROLOGUE after
	 * LLVM_TESTCASE_KBUILD, so if kbuild test failed,
	 * don't need to try this one, because it depend on
	 * kernel header.
	 */
	LLVM_TESTCASE_BPF_PROLOGUE,
	NR_LLVM_TESTCASES,
};
void test_llvm__fetch_bpf_obj(void **p_obj_buf, size_t *p_obj_buf_sz, int index);

#endif
