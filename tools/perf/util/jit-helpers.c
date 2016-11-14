/*
 * jit-helper.c
 *
 * Copyright (C) 2016 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2016 Huawei Inc.
 *
 * Provide helpers which can be invoked by jit scripts attached to
 * perf hooks.
 */

#include <util/jit-helpers.h>
#include <util/bpf-loader.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "asm/bug.h"

static int get_bpf_map_fd(struct bpf_object *obj, void *map)
{
	int fd;
	char errbuf[BUFSIZ];

	fd = bpf__map_fd(obj, map);
	if (fd < 0) {
		bpf__strerror_map_fd(obj, map, fd, errbuf, sizeof(errbuf));
		WARN_ONCE(fd < 0, "Failed to get map fd: %s\n", errbuf);
	}
	return fd;
}

#define PARAMS(args...) args
#define DEFINE_JIT_BPF_MAP_HELPER(name, proto, args)			\
	JIT_BPF_MAP_HELPER(name, proto) {				\
		int map_fd = get_bpf_map_fd(ctx, map);			\
									\
		if (map_fd < 0)						\
			return map_fd;					\
		return bpf_map_##name(map_fd, args);			\
	}

DEFINE_JIT_BPF_MAP_HELPER(update_elem,
			  PARAMS(void *key, void *value, u64 flags),
			  PARAMS(key, value, flags))

DEFINE_JIT_BPF_MAP_HELPER(lookup_elem,
			  PARAMS(void *key, void *value),
			  PARAMS(key, value))

DEFINE_JIT_BPF_MAP_HELPER(get_next_key,
			  PARAMS(void *key, void *next_key),
			  PARAMS(key, next_key))

DEFINE_JIT_BPF_MAP_HELPER(pin,
			  PARAMS(const char *pathname),
			  PARAMS(pathname));

JIT_HELPER(int, map_get, const char *pathname)
{
	return bpf_map_get(pathname);
}
