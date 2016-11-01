#include "clang.h"
#include "clang-c.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"

#include <util-cxx.h>
#include <tests/llvm.h>
#include <perf-hooks.h>
#include <string>

class perf_clang_scope {
public:
	explicit perf_clang_scope() {perf_clang__init();}
	~perf_clang_scope() {perf_clang__cleanup();}
};

static std::unique_ptr<perf::PerfModule>
__test__clang_to_IR(bool perfhook)
{
	unsigned int kernel_version;

	if (fetch_kernel_version(&kernel_version, NULL, 0))
		return std::unique_ptr<perf::PerfModule>(nullptr);

	std::string cflag_kver("-DLINUX_VERSION_CODE=" +
				std::to_string(kernel_version));
	std::string cflag_perfhook(perfhook ? "-DTEST_PERF_HOOK=1" : "");

	std::unique_ptr<perf::PerfModule> M =
		perf::getModuleFromSource({cflag_kver.c_str(),
					   cflag_perfhook.c_str()},
					  "perf-test.c",
					  test_llvm__bpf_base_prog);
	return M;
}

static std::unique_ptr<perf::PerfModule>
__test__clang_to_IR(void)
{
	return __test__clang_to_IR(false);
}

extern "C" {
int test__clang_to_IR(void)
{
	perf_clang_scope _scope;

	auto M = __test__clang_to_IR();
	if (!M)
		return -1;
	for (llvm::Function& F : *(M->getModule()))
		if (F.getName() == "bpf_func__SyS_epoll_wait")
			return 0;
	return -1;
}

int test__clang_to_obj(void)
{
	perf_clang_scope _scope;

	auto M = __test__clang_to_IR();
	if (!M)
		return -1;

	auto Buffer = M->toBPFObject();
	if (!Buffer)
		return -1;
	return 0;
}

int test__clang_jit(void)
{
	perf_clang_scope _scope;

	auto M = __test__clang_to_IR(true);
	if (!M)
		return -1;

	if (M->doJIT())
		return -1;

	std::unique_ptr<perf::PerfModule::HookMap> hooks(M->copyJITResult());
	for (auto i : *hooks)
		perf_hooks__set_hook(i.first.c_str(), i.second, NULL);

	perf_hooks__invoke_test();
	return 0;
}

}
