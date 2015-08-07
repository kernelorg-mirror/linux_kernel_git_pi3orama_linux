/*
 * Copyright (C) 2015, Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015, Huawei Inc.
 */
#ifndef __BPF_LOADER_H
#define __BPF_LOADER_H

#include <linux/compiler.h>
#include <string.h>
#include "debug.h"

#define PERF_BPF_PROBE_GROUP "perf_bpf_probe"

#ifdef HAVE_LIBBPF_SUPPORT
int bpf__prepare_load(const char *filename);
int bpf__strerror_prepare_load(const char *filename, int err,
			       char *buf, size_t size);
int bpf__probe(void);
int bpf__unprobe(void);
int bpf__strerror_probe(int err, char *buf, size_t size);

void bpf__clear(void);
#else
static inline int bpf__prepare_load(const char *filename __maybe_unused)
{
	pr_debug("ERROR: eBPF object loading is disabled during compiling.\n");
	return -1;
}

static inline int bpf__probe(void) { return 0; }
static inline int bpf__unprobe(void) { return 0; }
static inline void bpf__clear(void) { }

static inline int
__bpf_strerror(char *buf, size_t size)
{
	if (!size)
		return 0;
	strncpy(buf,
		"ERROR: eBPF object loading is disabled during compiling.\n",
		size);
	buf[size - 1] = '\0';
	return 0;
}

static inline int
bpf__strerror_prepare_load(const char *filename __maybe_unused,
			   int err __maybe_unused,
			   char *buf, size_t size)
{
	return __bpf_strerror(buf, size);
}

static inline int bpf__strerror_probe(int err __maybe_unused,
				      char *buf, size_t size)
{
	return __bpf_strerror(buf, size);
}
#endif
#endif
