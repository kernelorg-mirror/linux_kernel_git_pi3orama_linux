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
#include "probe-event.h"
#include "probe-finder.h"

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

static int
config_bpf_program(struct bpf_program *prog, struct perf_probe_event *pev)
{
	const char *config_str;
	int err;

	config_str = bpf_program__title(prog, false);
	if (!config_str) {
		pr_debug("bpf: unable to get title for program\n");
		return -EINVAL;
	}

	pr_debug("bpf: config program '%s'\n", config_str);
	err = parse_perf_probe_command(config_str, pev);
	if (err < 0) {
		pr_debug("bpf: '%s' is not a valid config string\n",
			 config_str);
		/* parse failed, don't need clear pev. */
		return -EINVAL;
	}

	if (pev->group && strcmp(pev->group, PERF_BPF_PROBE_GROUP)) {
		pr_debug("bpf: '%s': group for event is set and not '%s'.\n",
			 config_str, PERF_BPF_PROBE_GROUP);
		err = -EINVAL;
		goto errout;
	} else if (!pev->group)
		pev->group = strdup(PERF_BPF_PROBE_GROUP);

	if (!pev->group) {
		pr_debug("bpf: strdup failed\n");
		err = -ENOMEM;
		goto errout;
	}

	if (!pev->event) {
		pr_debug("bpf: '%s': event name is missing\n",
			 config_str);
		err = -EINVAL;
		goto errout;
	}

	pr_debug("bpf: config '%s' is ok\n", config_str);

	return 0;

errout:
	if (pev)
		clear_perf_probe_event(pev);
	return err;
}

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

static bool is_probed;

int bpf__unprobe(void)
{
	struct strfilter *delfilter;
	int ret;

	if (!is_probed)
		return 0;

	delfilter = strfilter__new(PERF_BPF_PROBE_GROUP ":*", NULL);
	if (!delfilter) {
		pr_debug("Failed to create delfilter when unprobing\n");
		return -ENOMEM;
	}

	ret = del_perf_probe_events(delfilter);
	strfilter__delete(delfilter);
	if (ret < 0 && is_probed)
		pr_debug("Error: failed to delete events: %s\n",
			 strerror(-ret));
	else
		is_probed = false;
	return ret < 0 ? ret : 0;
}

int bpf__probe(void)
{
	int err, nr_events = 0;
	struct bpf_object *obj, *tmp;
	struct bpf_program *prog;
	struct perf_probe_event *pevs;

	pevs = calloc(MAX_PROBES, sizeof(pevs[0]));
	if (!pevs)
		return -ENOMEM;

	bpf_object__for_each_safe(obj, tmp) {
		bpf_object__for_each_program(prog, obj) {
			err = config_bpf_program(prog, &pevs[nr_events++]);
			if (err < 0)
				goto out;

			if (nr_events >= MAX_PROBES) {
				pr_debug("Too many (more than %d) events\n",
					 MAX_PROBES);
				err = -ERANGE;
				goto out;
			};
		}
	}

	probe_conf.max_probes = MAX_PROBES;
	/* Let add_perf_probe_events generates probe_trace_event (tevs) */
	err = add_perf_probe_events(pevs, nr_events, false);

	/* add_perf_probe_events return negative when fail */
	if (err < 0) {
		pr_debug("bpf probe: failed to probe events\n");
	} else
		is_probed = true;
out:
	while (nr_events > 0)
		clear_perf_probe_event(&pevs[--nr_events]);
	free(pevs);
	return err < 0 ? err : 0;
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

int bpf__strerror_probe(int err, char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(ERANGE, "Too many (more than %d) events",
			    MAX_PROBES);
	bpf__strerror_entry(ENOENT, "Selected kprobe point doesn't exist.");
	bpf__strerror_entry(EEXIST, "Selected kprobe point already exist, try perf probe -d '*'.");
	bpf__strerror_end(buf, size);
	return 0;
}
