#ifndef PERF_UTIL_CLANG_H
#define PERF_UTIL_CLANG_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Option/Option.h"
#include <memory>
#include <set>

namespace perf {

using namespace llvm;

class PerfModule {
private:
	std::unique_ptr<llvm::Module> Module;

	std::set<llvm::GlobalVariable *> Maps;
	std::set<llvm::Function *> BPFFunctions;
	std::set<llvm::Function *> JITFunctions;
	void prepareBPF(void);
	void prepareJIT(void);
public:
	inline llvm::Module *getModule(void)
	{
		return Module.get();
	}

	PerfModule(std::unique_ptr<llvm::Module>&& M);

	std::unique_ptr<llvm::SmallVectorImpl<char>> toBPFObject(void);
};

std::unique_ptr<PerfModule>
getModuleFromSource(opt::ArgStringList CFlags,
		    StringRef Name, StringRef Content);

std::unique_ptr<PerfModule>
getModuleFromSource(opt::ArgStringList CFlags,
		    StringRef Path);
}
#endif
