#include <stdio.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include <util/llvm-utils.h>
#include <util/cache.h>
#include <util/util.h>
#include <sys/mman.h>
#include "tests.h"
#include "debug.h"
#include "llvm.h"

static int perf_config_cb(const char *var, const char *val,
			  void *arg __maybe_unused)
{
	return perf_default_config(var, val, arg);
}

#ifdef HAVE_LIBBPF_SUPPORT
static int test__bpf_parsing(void *obj_buf, size_t obj_buf_sz)
{
	struct bpf_object *obj;

	obj = bpf_object__open_buffer(obj_buf, obj_buf_sz, NULL);
	if (!obj)
		return -1;
	bpf_object__close(obj);
	return 0;
}
#else
static int test__bpf_parsing(void *obj_buf __maybe_unused,
			     size_t obj_buf_sz __maybe_unused)
{
	fprintf(stderr, " (skip bpf parsing)");
	return 0;
}
#endif

static char *
compose_source(void)
{
	struct utsname utsname;
	int version, patchlevel, sublevel, err;
	unsigned long version_code;
	char *code;

	if (uname(&utsname))
		return NULL;

	err = sscanf(utsname.release, "%d.%d.%d",
		     &version, &patchlevel, &sublevel);
	if (err != 3) {
		fprintf(stderr, " (Can't get kernel version from uname '%s')",
			utsname.release);
		return NULL;
	}

	version_code = (version << 16) + (patchlevel << 8) + sublevel;
	err = asprintf(&code, "#define LINUX_VERSION_CODE 0x%08lx;\n%s",
		       version_code, test_llvm__bpf_prog);
	if (err < 0)
		return NULL;

	return code;
}

#define SHARED_BUF_INIT_SIZE	(1 << 20)
struct test_llvm__bpf_result *p_test_llvm__bpf_result;

int test__llvm(void)
{
	char *tmpl_new, *clang_opt_new;
	void *obj_buf;
	size_t obj_buf_sz;
	int err, old_verbose;
	char *source;

	perf_config(perf_config_cb, NULL);

	/*
	 * Skip this test if user's .perfconfig doesn't set [llvm] section
	 * and clang is not found in $PATH, and this is not perf test -v
	 */
	if (verbose == 0 && !llvm_param.user_set_param && llvm__search_clang()) {
		fprintf(stderr, " (no clang, try 'perf test -v LLVM')");
		return TEST_SKIP;
	}

	old_verbose = verbose;
	/*
	 * llvm is verbosity when error. Suppress all error output if
	 * not 'perf test -v'.
	 */
	if (verbose == 0)
		verbose = -1;

	if (!llvm_param.clang_bpf_cmd_template)
		return -1;

	if (!llvm_param.clang_opt)
		llvm_param.clang_opt = strdup("");

	source = compose_source();
	if (!source) {
		pr_err("Failed to compose source code\n");
		return -1;
	}

	/* Quote __EOF__ so strings in source won't be expanded by shell */
	err = asprintf(&tmpl_new, "cat << '__EOF__' | %s\n%s\n__EOF__\n",
		       llvm_param.clang_bpf_cmd_template, source);
	free(source);
	source = NULL;
	if (err < 0) {
		pr_err("Failed to alloc new template\n");
		return -1;
	}

	err = asprintf(&clang_opt_new, "-xc %s", llvm_param.clang_opt);
	if (err < 0)
		return -1;

	llvm_param.clang_bpf_cmd_template = tmpl_new;
	llvm_param.clang_opt = clang_opt_new;
	err = llvm__compile_bpf("-", &obj_buf, &obj_buf_sz);

	verbose = old_verbose;
	if (err) {
		if (!verbose)
			fprintf(stderr, " (use -v to see error message)");
		return -1;
	}

	err = test__bpf_parsing(obj_buf, obj_buf_sz);
	if (!err && p_test_llvm__bpf_result) {
		if (obj_buf_sz > SHARED_BUF_INIT_SIZE) {
			pr_err("Resulting object too large\n");
		} else {
			p_test_llvm__bpf_result->size = obj_buf_sz;
			memcpy(p_test_llvm__bpf_result->object,
			       obj_buf, obj_buf_sz);
		}
	}
	free(obj_buf);
	return err;
}

void test__llvm_prepare(void)
{
	p_test_llvm__bpf_result = mmap(NULL, SHARED_BUF_INIT_SIZE,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!p_test_llvm__bpf_result)
		return;
	memset((void *)p_test_llvm__bpf_result, '\0', SHARED_BUF_INIT_SIZE);
}

void test__llvm_cleanup(void)
{
	unsigned long boundary, buf_end;

	if (!p_test_llvm__bpf_result)
		return;
	if (p_test_llvm__bpf_result->size == 0) {
		munmap((void *)p_test_llvm__bpf_result, SHARED_BUF_INIT_SIZE);
		p_test_llvm__bpf_result = NULL;
		return;
	}

	buf_end = (unsigned long)p_test_llvm__bpf_result + SHARED_BUF_INIT_SIZE;

	boundary = (unsigned long)(p_test_llvm__bpf_result);
	boundary += p_test_llvm__bpf_result->size;
	boundary = (boundary + (page_size - 1)) &
			(~((unsigned long)page_size - 1));
	munmap((void *)boundary, buf_end - boundary);
}
