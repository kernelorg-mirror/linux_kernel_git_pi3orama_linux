/*
 * bpf-loader.c
 *
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 */

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "perf.h"
#include "debug.h"
#include "bpf-loader.h"
#include "bpf-prologue.h"
#include "llvm-utils.h"
#include "probe-event.h"
#include "probe-finder.h"
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

static bool libbpf_initialized;

struct bpf_prog_priv {
	/*
	 * If pev_ready is false, ppev pointes to a local memory which
	 * is only valid inside bpf__probe().
	 * pev is valid only when pev_ready.
	 */
	bool pev_ready;
	union {
		struct perf_probe_event *ppev;
		struct perf_probe_event pev;
	};
	bool need_prologue;
	struct bpf_insn *insns_buf;
};

static void
bpf_prog_priv__clear(struct bpf_program *prog __maybe_unused,
			  void *_priv)
{
	struct bpf_prog_priv *priv = _priv;

	/* check if pev is initialized */
	if (priv && priv->pev_ready)
		clear_perf_probe_event(&priv->pev);
	zfree(&priv->insns_buf);
	free(priv);
}

static int
config_bpf_program(struct bpf_program *prog, struct perf_probe_event *pev)
{
	struct bpf_prog_priv *priv = NULL;
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

	priv = calloc(1, sizeof(*priv));
	if (!priv) {
		pr_debug("bpf: failed to alloc memory\n");
		err = -ENOMEM;
		goto errout;
	}

	/*
	 * At this very early stage, tevs inside pev are not ready.
	 * It becomes usable after add_perf_probe_events() is called.
	 * set pev_ready to false so further access read priv->ppev
	 * only.
	 */
	priv->pev_ready = false;
	priv->ppev = pev;

	err = bpf_program__set_private(prog, priv,
				       bpf_prog_priv__clear);
	if (err) {
		pr_debug("bpf: set program private failed\n");
		err = -ENOMEM;
		goto errout;
	}
	return 0;

errout:
	if (pev)
		clear_perf_probe_event(pev);
	if (priv)
		free(priv);
	return err;
}

static int
sync_bpf_program_pev(struct bpf_program *prog)
{
	int err;
	struct bpf_prog_priv *priv;
	struct perf_probe_event *ppev;

	err = bpf_program__get_private(prog, (void **)&priv);
	if (err || !priv || priv->pev_ready) {
		pr_debug("Internal error: sync_bpf_program_pev\n");
		return -EINVAL;
	}

	ppev = priv->ppev;
	memcpy(&priv->pev, ppev, sizeof(*ppev));
	priv->pev_ready = true;
	return 0;
}

int bpf__prepare_load_buffer(void *obj_buf, size_t obj_buf_sz)
{
	struct bpf_object *obj;

	obj = bpf_object__open_buffer(obj_buf, obj_buf_sz);
	if (!obj) {
		pr_debug("bpf: failed to load buffer\n");
		return -EINVAL;
	}

	return 0;
}

int bpf__prepare_load(const char *filename, bool source)
{
	struct bpf_object *obj;
	int err;

	if (!libbpf_initialized)
		libbpf_set_print(libbpf_warning,
				 libbpf_info,
				 libbpf_debug);

	if (source) {
		void *obj_buf;
		size_t obj_buf_sz;

		err = llvm__compile_bpf(filename, &obj_buf, &obj_buf_sz);
		if (err)
			return err;
		obj = bpf_object__open_buffer(obj_buf, obj_buf_sz);
		free(obj_buf);
	} else
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
	bool old_silent = probe_conf.silent;
	int ret;

	if (!is_probed)
		return 0;

	delfilter = strfilter__new(PERF_BPF_PROBE_GROUP ":*", NULL);
	if (!delfilter) {
		pr_debug("Failed to create delfilter when unprobing\n");
		return -ENOMEM;
	}

	probe_conf.silent = true;
	ret = del_perf_probe_events(delfilter);
	probe_conf.silent = old_silent;
	strfilter__delete(delfilter);
	if (ret < 0 && is_probed)
		pr_debug("Error: failed to delete events: %s\n",
			 strerror(-ret));
	else
		is_probed = false;
	return ret < 0 ? ret : 0;
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
	int err;

	err = bpf_program__get_private(prog, (void **)&priv);
	if (err || !priv || !priv->pev_ready)
		goto errout;

	pev = &priv->pev;

	if (n < 0 || n >= pev->ntevs)
		goto errout;

	tev = &pev->tevs[n];

	buf = priv->insns_buf;
	err = bpf__gen_prologue(tev->args, tev->nargs,
				buf, &prologue_cnt,
				BPF_MAXINSNS - orig_insns_cnt);
	if (err) {
		const char *title;

		title = bpf_program__title(prog, false);
		if (!title)
			title = "??";

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
	priv->insns_buf = malloc(sizeof(struct bpf_insn) *
					BPF_MAXINSNS);
	if (!priv->insns_buf) {
		pr_debug("No enough memory: alloc insns_buf failed\n");
		return -ENOMEM;
	}

	err = bpf_program__set_prep(prog, pev->ntevs,
				    preproc_gen_prologue);
	return err;
}

int bpf__probe(void)
{
	int err, nr_events = 0;
	struct bpf_object *obj, *tmp;
	struct bpf_program *prog;
	struct perf_probe_event *pevs;
	bool old_silent = probe_conf.silent;

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

	probe_conf.silent = true;
	probe_conf.max_probes = MAX_PROBES;
	/* Let add_perf_probe_events generates probe_trace_event (tevs) */
	err = add_perf_probe_events(pevs, nr_events, false);
	probe_conf.silent = old_silent;

	/* add_perf_probe_events return negative when fail */
	if (err < 0) {
		pr_debug("bpf probe: failed to probe events\n");
		goto out;
	} else
		is_probed = true;

	/*
	 * After add_perf_probe_events, 'struct perf_probe_event' is ready.
	 * Until now copying program's priv->pev field and freeing
	 * the big array allocated before become safe.
	 */
	bpf_object__for_each_safe(obj, tmp) {
		bpf_object__for_each_program(prog, obj) {
			err = sync_bpf_program_pev(prog);
			if (err)
				goto out;
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
	}
out:
	/*
	 * Don't call clear_perf_probe_event() for entries of pevs:
	 * they are used by prog's private field.
	 */
	free(pevs);
	return err < 0 ? err : 0;
}

int bpf__load(void)
{
	struct bpf_object *obj, *tmp;
	int err = 0;

	bpf_object__for_each_safe(obj, tmp) {
		err = bpf_object__load(obj);
		if (err) {
			pr_debug("bpf: load objects failed\n");
			goto errout;
		}
	}
	return 0;
errout:
	bpf_object__for_each_safe(obj, tmp)
		bpf_object__unload(obj);
	return err;
}

int bpf__foreach_tev(bpf_prog_iter_callback_t func, void *arg)
{
	struct bpf_object *obj, *tmp;
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_safe(obj, tmp) {
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

				if (priv->need_prologue)
					fd = bpf_program__nth_fd(prog, i);
				else
					fd = bpf_program__fd(prog);

				if (fd < 0) {
					pr_debug("bpf: failed to get file descriptor\n");
					return fd;
				}

				err = func(tev, fd, arg);
				if (err) {
					pr_debug("bpf: call back failed, stop iterate\n");
					return err;
				}
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

int bpf__strerror_prepare_load(const char *filename, bool source,
			       int err, char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(EINVAL, "%s: BPF %s file '%s' is invalid",
			    emsg, source ? "source" : "object", filename);
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

int bpf__strerror_load(int err, char *buf, size_t size)
{
	bpf__strerror_head(err, buf, size);
	bpf__strerror_entry(EINVAL, "%s: add -v to see detail. Run a CONFIG_BPF_SYSCALL kernel?",
			    emsg)
	bpf__strerror_end(buf, size);
	return 0;
}
