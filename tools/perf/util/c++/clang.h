#ifndef PERF_UTIL_CLANG_H
#define PERF_UTIL_CLANG_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Option/Option.h"
#include <memory>
#include <set>
#include <map>

#include "util/perf-hooks.h"

namespace perf {

using namespace llvm;

class PerfModule {
public:
	typedef std::map<std::string, perf_hook_func_t> HookMap;
private:
	std::unique_ptr<llvm::Module> Module;

	std::set<llvm::GlobalVariable *> Maps;
	std::set<llvm::Function *> BPFFunctions;
	std::set<llvm::Function *> JITFunctions;

	HookMap JITResult;

	void prepareBPF(void);
	void prepareJIT(void);
public:
	inline llvm::Module *getModule(void)
	{
		return Module.get();
	}
	inline HookMap *copyJITResult(void)
	{
		return new HookMap(JITResult);
	}

	PerfModule(std::unique_ptr<llvm::Module>&& M);

	std::unique_ptr<llvm::SmallVectorImpl<char>> toBPFObject(void);
	int doJIT(void);
};

std::unique_ptr<PerfModule>
getModuleFromSource(opt::ArgStringList CFlags,
		    StringRef Name, StringRef Content);

std::unique_ptr<PerfModule>
getModuleFromSource(opt::ArgStringList CFlags,
		    StringRef Path);
}
#endif
