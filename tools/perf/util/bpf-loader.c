/*
 * bpf-loader.c
 *
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 */

#include <bpf/libbpf.h>
#include "perf.h"
#include "debug.h"
#include "bpf-loader.h"

#define DEFINE_PRINT_FN(name, level) \
static int libbpf_##name(const char *fmt, ...)	\
{						\
	va_list args;				\
	int ret;				\
						\
	va_start(args, fmt);			\
	ret = veprintf(level, verbose, pr_fmt(fmt), args);\
	va_end(args);				\
	return ret;				\
}

DEFINE_PRINT_FN(warning, 0)
DEFINE_PRINT_FN(info, 0)
DEFINE_PRINT_FN(debug, 1)

static bool libbpf_initialized;

int bpf__prepare_load(const char *filename)
{
	struct bpf_object *obj;

	if (!libbpf_initialized)
		libbpf_set_print(libbpf_warning,
				 libbpf_info,
				 libbpf_debug);

	obj = bpf_object__open(filename);
	if (!obj) {
		pr_debug("bpf: failed to load %s\n", filename);
		return -EINVAL;
	}

	/*
	 * Throw object pointer away: it will be retrived using
	 * bpf_objects iterater.
	 */

	return 0;
}

void bpf__clear(void)
{
	struct bpf_object *obj, *tmp;

	bpf_object__for_each_safe(obj, tmp)
		bpf_object__close(obj);
}

#define bpf__strerror_head(err, buf, size) \
	char sbuf[STRERR_BUFSIZE], *emsg;\
	if (!size)\
		return 0;\
	if (err < 0)\
		err = -err;\
	emsg = strerror_r(err, sbuf, sizeof(sbuf));\
	switch (err) {\
	default:\
		scnprintf(buf, size, "%s", emsg);\
		break;

#define bpf__strerror_entry(val, fmt...)\
	case val: {\
		scnprintf(buf, size, fmt);\
		break;\
	}

#define bpf__strerror_end(buf, size)\
	}\
	buf[size - 1] = '\0';

int bpf__strerror_prepare_load(const char *filename, int err,
			       char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(EINVAL, "%s: BPF object file '%s' is invalid",
			    emsg, filename)
	bpf__strerror_end(buf, size);
	return 0;
}
