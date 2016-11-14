#ifndef JIT_HELPERS_H
#define JIT_HELPERS_H

#include <stdint.h>
#include <util/perf-hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JIT_HELPER_FUNC_NAME(name) jit_helper__##name

#define JIT_HELPER(type, name, ...) \
type JIT_HELPER_FUNC_NAME(name)(__VA_ARGS__)

#define JIT_BPF_MAP_HELPER(name, ...) \
	JIT_HELPER(int, map_##name, void *ctx, void *map, ##__VA_ARGS__)

extern JIT_BPF_MAP_HELPER(update_elem, void *key, void *value, uint64_t flags);
extern JIT_BPF_MAP_HELPER(lookup_elem, void *key, void *value);
extern JIT_BPF_MAP_HELPER(get_next_key, void *key, void *next_key);
extern JIT_BPF_MAP_HELPER(pin, const char *pathname);

extern JIT_HELPER(int, map_get, const char *pathname);

#ifdef __cplusplus
}
#endif

#endif
