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

#define SHARED_BUF_INIT_SIZE	(1 << 20)
struct llvm_testcase {
	const char *source;
	const char *errmsg;
	struct test_llvm__bpf_result *result;
	bool tried;
} llvm_testcases[NR_LLVM_TESTCASES + 1] = {
	[LLVM_TESTCASE_BASE]	= {.source = test_llvm__bpf_prog,
				   .errmsg = "Basic LLVM compiling failed",
				   .tried = false},
	[LLVM_TESTCASE_KBUILD]	= {.source = test_llvm__bpf_test_kbuild_prog,
				   .errmsg = "llvm.kbuild-dir can be fixed",
				   .tried = false},
	/* Don't output if this one fail. */
	[LLVM_TESTCASE_BPF_PROLOGUE]	= {
				   .source = test_llvm__bpf_test_prologue_prog,
				   .errmsg = "failed for unknown reason",
				   .tried = false},
	{.source = NULL}
};

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
compose_source(const char *raw_source)
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
		       version_code, raw_source);
	if (err < 0)
		return NULL;

	return code;
}


static int __test__llvm(int i)
{
	void *obj_buf;
	size_t obj_buf_sz;
	int err, old_verbose;
	const char *tmpl_old, *clang_opt_old;
	char *tmpl_new, *clang_opt_new, *source;
	const char *raw_source = llvm_testcases[i].source;
	struct test_llvm__bpf_result *result = llvm_testcases[i].result;

	perf_config(perf_config_cb, NULL);
	clang_opt_old = llvm_param.clang_opt;
	tmpl_old = llvm_param.clang_bpf_cmd_template;

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

	source = compose_source(raw_source);
	if (!source) {
		pr_err("Failed to compose source code\n");
		return -1;
	}

	/* Quote __EOF__ so strings in source won't be expanded by shell */
	err = asprintf(&tmpl_new, "cat << '__EOF__' | %s %s \n%s\n__EOF__\n",
		       llvm_param.clang_bpf_cmd_template,
		       !old_verbose ? "2>/dev/null" : "",
		       source);
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

	free((void *)llvm_param.clang_bpf_cmd_template);
	free((void *)llvm_param.clang_opt);
	llvm_param.clang_bpf_cmd_template = tmpl_old;
	llvm_param.clang_opt = clang_opt_old;

	verbose = old_verbose;
	if (err)
		return -1;

	err = test__bpf_parsing(obj_buf, obj_buf_sz);
	if (!err && result) {
		if (obj_buf_sz > SHARED_BUF_INIT_SIZE) {
			pr_err("Resulting object too large\n");
		} else {
			result->size = obj_buf_sz;
			memcpy(result->object, obj_buf, obj_buf_sz);
		}
	}
	free(obj_buf);
	return err;
}

int test__llvm(void)
{
	int i, ret;

	for (i = 0; llvm_testcases[i].source; i++) {
		ret = __test__llvm(i);
		if (i == 0 && ret) {
			/*
			 * First testcase tests basic LLVM compiling. If it
			 * fails, no need to check others.
			 */
			if (!verbose)
				fprintf(stderr, " (use -v to see error message)");
			return ret;
		} else if (ret) {
			if (!verbose && llvm_testcases[i].errmsg)
				fprintf(stderr, " (%s)", llvm_testcases[i].errmsg);
			return 0;
		}
	}
	return 0;
}

void test__llvm_prepare(void)
{
	int i;

	for (i = 0; llvm_testcases[i].source; i++) {
		struct test_llvm__bpf_result *result;

		result = mmap(NULL, SHARED_BUF_INIT_SIZE,
			      PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (!result)
			return;
		memset((void *)result, '\0', SHARED_BUF_INIT_SIZE);

		llvm_testcases[i].result = result;
	}
}

void test__llvm_cleanup(void)
{
	int i;

	for (i = 0; llvm_testcases[i].source; i++) {
		struct test_llvm__bpf_result *result;
		unsigned long boundary, buf_end;

		result = llvm_testcases[i].result;
		llvm_testcases[i].tried = true;

		if (!result)
			continue;

		if (result->size == 0) {
			munmap((void *)result, SHARED_BUF_INIT_SIZE);
			result = NULL;
			llvm_testcases[i].result = NULL;
			continue;
		}

		buf_end = (unsigned long)result + SHARED_BUF_INIT_SIZE;

		boundary = (unsigned long)(result);
		boundary += result->size;
		boundary = (boundary + (page_size - 1)) &
			(~((unsigned long)page_size - 1));
		munmap((void *)boundary, buf_end - boundary);
	}
}

void
test_llvm__fetch_bpf_obj(void **p_obj_buf, size_t *p_obj_buf_sz, int index)
{
	struct test_llvm__bpf_result *result;

	*p_obj_buf = NULL;
	*p_obj_buf_sz = 0;

	if (index > NR_LLVM_TESTCASES)
		return;

	result = llvm_testcases[index].result;

	if (!result && !llvm_testcases[index].tried) {
		test__llvm_prepare();
		test__llvm();
		test__llvm_cleanup();
	}

	result = llvm_testcases[index].result;
	if (!result)
		return;

	*p_obj_buf = result->object;
	*p_obj_buf_sz = result->size;
}
