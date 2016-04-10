#include <stdlib.h>
#include <ubpf.h>

int main(void)
{
	struct ubpf_vm *vm;

	vm = ubpf_create();
	ubpf_destroy(vm);
	return 0;
}
