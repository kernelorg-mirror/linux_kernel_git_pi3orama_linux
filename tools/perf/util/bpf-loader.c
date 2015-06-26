/*
 * bpf-loader.c
 *
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 */

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <linux/err.h>
#include "perf.h"
#include "debug.h"
#include "bpf-loader.h"
#include "bpf-prologue.h"
#include "llvm-utils.h"
#include "probe-event.h"
#include "probe-finder.h" // for MAX_PROBES
#include "llvm-utils.h"

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

struct bpf_prog_priv {
	struct perf_probe_event pev;
	bool need_prologue;
	struct bpf_insn *insns_buf;
	int nr_types;
	int *type_mapping;
};

struct bpf_object *
bpf__prepare_load_buffer(void *obj_buf, size_t obj_buf_sz, const char *name)
{
	struct bpf_object *obj;

	obj = bpf_object__open_buffer(obj_buf, obj_buf_sz, name);
	if (!obj) {
		pr_debug("bpf: failed to load buffer\n");
		return ERR_PTR(-EINVAL);
	}

	return obj;
}

struct bpf_object *bpf__prepare_load(const char *filename, bool source)
{
	struct bpf_object *obj;
	static bool libbpf_initialized;

	if (!libbpf_initialized) {
		libbpf_set_print(libbpf_warning,
				 libbpf_info,
				 libbpf_debug);
		libbpf_initialized = true;
	}

	if (source) {
		int err;
		void *obj_buf;
		size_t obj_buf_sz;

		err = llvm__compile_bpf(filename, &obj_buf, &obj_buf_sz);
		if (err)
			return ERR_PTR(err);
		obj = bpf_object__open_buffer(obj_buf, obj_buf_sz, filename);
		free(obj_buf);
	} else
		obj = bpf_object__open(filename);

	if (!obj) {
		pr_debug("bpf: failed to load %s\n", filename);
		return ERR_PTR(-EINVAL);
	}

	return obj;
}

void bpf__clear(void)
{
	struct bpf_object *obj, *tmp;

	bpf_object__for_each_safe(obj, tmp) {
		bpf__unprobe(obj);
		bpf_object__close(obj);
	}
}

static void
bpf_prog_priv__clear(struct bpf_program *prog __maybe_unused,
		     void *_priv)
{
	struct bpf_prog_priv *priv = _priv;

	cleanup_perf_probe_events(&priv->pev, 1);
	zfree(&priv->insns_buf);
	zfree(&priv->type_mapping);
	free(priv);
}

static int
do_config(const char *key, const char *value,
	  struct perf_probe_event *pev)
{
	pr_debug("config bpf program: %s=%s\n", key, value);
	if (strcmp(key, "target") == 0) {
		pev->uprobes = true;
		pev->target = strdup(value);
		return 0;
	}

	pr_warning("BPF: WARNING: invalid config option in object: %s=%s\n",
		   key, value);
	pr_warning("\tHint: Currently only valid option is 'target=<file>'\n");
	return 0;
}

static const char *
parse_config_kvpair(const char *config_str, struct perf_probe_event *pev)
{
	char *text = strdup(config_str);
	char *sep, *line;
	const char *main_str = NULL;
	int err = 0;

	if (!text) {
		pr_debug("No enough memory: dup config_str failed\n");
		return NULL;
	}

	line = text;
	while ((sep = strchr(line, '\n'))) {
		char *equ;

		*sep = '\0';
		equ = strchr(line, '=');
		if (!equ) {
			pr_warning("WARNING: invalid config in BPF object: %s\n",
				   line);
			pr_warning("\tShould be 'key=value'.\n");
			goto nextline;
		}
		*equ = '\0';

		err = do_config(line, equ + 1, pev);
		if (err)
			break;
nextline:
		line = sep + 1;
	}

	if (!err)
		main_str = config_str + (line - text);
	free(text);

	return main_str;
}

static int
parse_config(const char *config_str, struct perf_probe_event *pev)
{
	const char *main_str;
	int err;

	main_str = parse_config_kvpair(config_str, pev);
	if (!main_str)
		return -EINVAL;

	err = parse_perf_probe_command(main_str, pev);
	if (err < 0) {
		pr_debug("bpf: '%s' is not a valid config string\n",
			 config_str);
		/* parse failed, don't need clear pev. */
		return -EINVAL;
	}
	return 0;
}

static int
config_bpf_program(struct bpf_program *prog)
{
	struct perf_probe_event *pev = NULL;
	struct bpf_prog_priv *priv = NULL;
	const char *config_str;
	int err;

	config_str = bpf_program__title(prog, false);
	if (!config_str) {
		pr_debug("bpf: unable to get title for program\n");
		return -EINVAL;
	}

	priv = calloc(sizeof(*priv), 1);
	if (!priv) {
		pr_debug("bpf: failed to alloc priv\n");
		return -ENOMEM;
	}
	pev = &priv->pev;

	pr_debug("bpf: config program '%s'\n", config_str);
	err = parse_config(config_str, pev);
	if (err)
		goto errout;

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

	err = bpf_program__set_private(prog, priv, bpf_prog_priv__clear);
	if (err) {
		pr_debug("Failed to set priv for program '%s'\n", config_str);
		goto errout;
	}

	return 0;

errout:
	if (pev)
		clear_perf_probe_event(pev);
	free(priv);
	return err;
}

static int bpf__prepare_probe(void)
{
	static int err = 0;
	static bool initialized = false;

	/*
	 * Make err static, so if init failed the first, bpf__prepare_probe()
	 * fails each time without calling init_probe_symbol_maps multiple
	 * times.
	 */
	if (initialized)
		return err;

	initialized = true;
	err = init_probe_symbol_maps(false);
	if (err < 0)
		pr_debug("Failed to init_probe_symbol_maps\n");
	probe_conf.max_probes = MAX_PROBES;
	return err;
}

static int
preproc_gen_prologue(struct bpf_program *prog, int n,
		     struct bpf_insn *orig_insns, int orig_insns_cnt,
		     struct bpf_prog_prep_result *res)
{
	struct probe_trace_event *tev;
	struct perf_probe_event *pev;
	struct bpf_prog_priv *priv;
	struct bpf_insn *buf;
	size_t prologue_cnt = 0;
	int i, err;

	err = bpf_program__get_private(prog, (void **)&priv);
	if (err || !priv)
		goto errout;

	pev = &priv->pev;

	if (n < 0 || n >= priv->nr_types)
		goto errout;

	/* Find a tev belongs to that type */
	for (i = 0; i < pev->ntevs; i++)
		if (priv->type_mapping[i] == n)
			break;

	if (i >= pev->ntevs) {
		pr_debug("Internal error: prologue type %d not found\n", n);
		return -ENOENT;
	}

	tev = &pev->tevs[i];

	buf = priv->insns_buf;
	err = bpf__gen_prologue(tev->args, tev->nargs,
				buf, &prologue_cnt,
				BPF_MAXINSNS - orig_insns_cnt);
	if (err) {
		const char *title;

		title = bpf_program__title(prog, false);
		if (!title)
			title = "[unknown]";

		pr_debug("Failed to generate prologue for program %s\n",
			 title);
		return err;
	}

	memcpy(&buf[prologue_cnt], orig_insns,
	       sizeof(struct bpf_insn) * orig_insns_cnt);

	res->new_insn_ptr = buf;
	res->new_insn_cnt = prologue_cnt + orig_insns_cnt;
	res->pfd = NULL;
	return 0;

errout:
	pr_debug("Internal error in preproc_gen_prologue\n");
	return -EINVAL;
}

/*
 * compare_tev_args is reflexive, transitive and antisymmetric.
 * I can show that but this margin is too narrow to contain.
 */
static int compare_tev_args(const void *ptev1, const void *ptev2)
{
	int i, ret;
	const struct probe_trace_event *tev1 =
		*(const struct probe_trace_event **)ptev1;
	const struct probe_trace_event *tev2 =
		*(const struct probe_trace_event **)ptev2;

	ret = tev2->nargs - tev1->nargs;
	if (ret)
		return ret;

	for (i = 0; i < tev1->nargs; i++) {
		struct probe_trace_arg *arg1, *arg2;
		struct probe_trace_arg_ref *ref1, *ref2;

		arg1 = &tev1->args[i];
		arg2 = &tev2->args[i];

		ret = strcmp(arg1->value, arg2->value);
		if (ret)
			return ret;

		ref1 = arg1->ref;
		ref2 = arg2->ref;

		while (ref1 && ref2) {
			ret = ref2->offset - ref1->offset;
			if (ret)
				return ret;

			ref1 = ref1->next;
			ref2 = ref2->next;
		}

		if (ref1 || ref2)
			return ref2 ? 1 : -1;
	}

	return 0;
}

static int map_prologue(struct perf_probe_event *pev, int *mapping,
			int *nr_types)
{
	int i, type = 0;
	struct {
		struct probe_trace_event *tev;
		int idx;
	} *stevs;
	size_t array_sz = sizeof(*stevs) * pev->ntevs;

	stevs = malloc(array_sz);
	if (!stevs) {
		pr_debug("No ehough memory: alloc stevs failed\n");
		return -ENOMEM;
	}

	pr_debug("In map_prologue, ntevs=%d\n", pev->ntevs);
	for (i = 0; i < pev->ntevs; i++) {
		stevs[i].tev = &pev->tevs[i];
		stevs[i].idx = i;
	}
	qsort(stevs, pev->ntevs, sizeof(*stevs),
	      compare_tev_args);

	for (i = 0; i < pev->ntevs; i++) {
		if (i == 0) {
			mapping[stevs[i].idx] = type;
			pr_debug("mapping[%d]=%d\n", stevs[i].idx,
				 type);
			continue;
		}

		if (compare_tev_args(stevs + i, stevs + i - 1) == 0)
			mapping[stevs[i].idx] = type;
		else
			mapping[stevs[i].idx] = ++type;

		pr_debug("mapping[%d]=%d\n", stevs[i].idx,
			 mapping[stevs[i].idx]);
	}
	free(stevs);
	*nr_types = type + 1;

	return 0;
}

static int hook_load_preprocessor(struct bpf_program *prog)
{
	struct perf_probe_event *pev;
	struct bpf_prog_priv *priv;
	bool need_prologue = false;
	int err, i;

	err = bpf_program__get_private(prog, (void **)&priv);
	if (err || !priv) {
		pr_debug("Internal error when hook preprocessor\n");
		return -EINVAL;
	}

	pev = &priv->pev;
	for (i = 0; i < pev->ntevs; i++) {
		struct probe_trace_event *tev = &pev->tevs[i];

		if (tev->nargs > 0) {
			need_prologue = true;
			break;
		}
	}

	/*
	 * Since all tev doesn't have argument, we don't need generate
	 * prologue.
	 */
	if (!need_prologue) {
		priv->need_prologue = false;
		return 0;
	}

	priv->need_prologue = true;
	priv->insns_buf = malloc(sizeof(struct bpf_insn) * BPF_MAXINSNS);
	if (!priv->insns_buf) {
		pr_debug("No enough memory: alloc insns_buf failed\n");
		return -ENOMEM;
	}

	priv->type_mapping = malloc(sizeof(int) * pev->ntevs);
	if (!priv->type_mapping) {
		pr_debug("No enough memory: alloc type_mapping failed\n");
		return -ENOMEM;
	}
	memset(priv->type_mapping, 0xff,
	       sizeof(int) * pev->ntevs);

	err = map_prologue(pev, priv->type_mapping, &priv->nr_types);
	if (err)
		return err;

	err = bpf_program__set_prep(prog, priv->nr_types,
				    preproc_gen_prologue);
	return err;
}

int bpf__probe(struct bpf_object *obj)
{
	int err = 0;
	struct bpf_program *prog;
	struct bpf_prog_priv *priv;
	struct perf_probe_event *pev;

	err = bpf__prepare_probe();
	if (err) {
		pr_debug("bpf__prepare_probe failed\n");
		return err;
	}

	bpf_object__for_each_program(prog, obj) {
		err = config_bpf_program(prog);
		if (err)
			goto out;

		err = bpf_program__get_private(prog, (void **)&priv);
		if (err || !priv)
			goto out;
		pev = &priv->pev;

		err = convert_perf_probe_events(pev, 1);
		if (err < 0) {
			pr_debug("bpf_probe: failed to convert perf probe events");
			goto out;
		}

		err = apply_perf_probe_events(pev, 1);
		if (err < 0) {
			pr_debug("bpf_probe: failed to apply perf probe events");
			goto out;
		}

		/*
		 * After probing, let's consider prologue, which
		 * adds program fetcher to BPF programs.
		 *
		 * hook_load_preprocessorr() hooks pre-processor
		 * to bpf_program, let it generate prologue
		 * dynamically during loading.
		 */
		err = hook_load_preprocessor(prog);
		if (err)
			goto out;
	}
out:
	return err < 0 ? err : 0;
}

#define EVENTS_WRITE_BUFSIZE  4096
int bpf__unprobe(struct bpf_object *obj)
{
	int err, ret = 0;
	struct bpf_program *prog;
	struct bpf_prog_priv *priv;

	bpf_object__for_each_program(prog, obj) {
		int i;

		err = bpf_program__get_private(prog, (void **)&priv);
		if (err || !priv)
			continue;

		for (i = 0; i < priv->pev.ntevs; i++) {
			struct probe_trace_event *tev = &priv->pev.tevs[i];
			char name_buf[EVENTS_WRITE_BUFSIZE];
			struct strfilter *delfilter;

			snprintf(name_buf, EVENTS_WRITE_BUFSIZE,
				 "%s:%s", tev->group, tev->event);
			name_buf[EVENTS_WRITE_BUFSIZE - 1] = '\0';

			delfilter = strfilter__new(name_buf, NULL);
			if (!delfilter) {
				pr_debug("Failed to create filter for unprobing\n");
				ret = -ENOMEM;
				continue;
			}

			err = del_perf_probe_events(delfilter);
			strfilter__delete(delfilter);
			if (err) {
				pr_debug("Failed to delete %s\n", name_buf);
				ret = err;
				continue;
			}
		}
	}
	return ret;
}

int bpf__load(struct bpf_object *obj)
{
	int err;

	err = bpf_object__load(obj);
	if (err) {
		pr_debug("bpf: load objects failed\n");
		return err;
	}
	return 0;
}

int bpf__foreach_tev(struct bpf_object *obj,
		     bpf_prog_iter_callback_t func,
		     void *arg)
{
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, obj) {
		struct probe_trace_event *tev;
		struct perf_probe_event *pev;
		struct bpf_prog_priv *priv;
		int i, fd;

		err = bpf_program__get_private(prog,
				(void **)&priv);
		if (err || !priv) {
			pr_debug("bpf: failed to get private field\n");
			return -EINVAL;
		}

		pev = &priv->pev;
		for (i = 0; i < pev->ntevs; i++) {
			tev = &pev->tevs[i];

			if (priv->need_prologue) {
				int type = priv->type_mapping[i];

				fd = bpf_program__nth_fd(prog, type);
			} else
				fd = bpf_program__fd(prog);

			if (fd < 0) {
				pr_debug("bpf: failed to get file descriptor\n");
				return fd;
			}

			err = (*func)(tev, fd, arg);
			if (err) {
				pr_debug("bpf: call back failed, stop iterate\n");
				return err;
			}
		}
	}
	return 0;
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

int bpf__strerror_probe(struct bpf_object *obj __maybe_unused,
			int err, char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(EEXIST, "Probe point exist. Try use 'perf probe -d \"*\"'");
	bpf__strerror_entry(EPERM, "You need to be root, and /proc/sys/kernel/kptr_restrict should be 0\n");
	bpf__strerror_entry(ENOENT, "You need to check probing points in BPF file\n");
	bpf__strerror_end(buf, size);
	return 0;
}

int bpf__strerror_load(struct bpf_object *obj __maybe_unused,
		       int err, char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(EINVAL, "%s: Are you root and runing a CONFIG_BPF_SYSCALL kernel?",
			    emsg)
	bpf__strerror_end(buf, size);
	return 0;
}
