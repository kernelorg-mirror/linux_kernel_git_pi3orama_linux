#include <stdio.h>
#include <sys/epoll.h>
#include <util/bpf-loader.h>
#include <util/evlist.h>
#include "tests.h"
#include "llvm.h"
#include "debug.h"
#define NR_ITERS       111

#ifdef HAVE_LIBBPF_SUPPORT

static int epoll_pwait_loop(void)
{
	int i;

	/* Should fail NR_ITERS times */
	for (i = 0; i < NR_ITERS; i++)
		epoll_pwait(-(i + 1), NULL, 0, 0, NULL);
	return 0;
}

#ifdef HAVE_BPF_PROLOGUE

static int llseek_loop(void)
{
	int fds[2], i;

	fds[0] = open("/dev/null", O_RDONLY);
	fds[1] = open("/dev/null", O_RDWR);

	if (fds[0] < 0 || fds[1] < 0)
		return -1;

	for (i = 0; i < NR_ITERS; i++) {
		lseek(fds[i % 2], i, (i / 2) % 2 ? SEEK_CUR : SEEK_SET);
		lseek(fds[(i + 1) % 2], i, (i / 2) % 2 ? SEEK_CUR : SEEK_SET);
	}
	close(fds[0]);
	close(fds[1]);
	return 0;
}

#endif

static struct bpf_object *prepare_bpf(const char *name, void *obj_buf,
				      size_t obj_buf_sz)
{
	struct bpf_object *obj;

	obj = bpf__prepare_load_buffer(obj_buf, obj_buf_sz, name);
	if (IS_ERR(obj)) {
		fprintf(stderr, " (compile failed)");
		return NULL;
	}
	return obj;
}

static int do_test(struct bpf_object *obj, int (*func)(void), int expect)
{
	struct record_opts opts = {
		.target = {
			.uid = UINT_MAX,
			.uses_mmap = true,
		},
		.freq	      = 0,
		.mmap_pages   = 256,
		.default_interval = 1,
	};

	int i, err = 0, count = 0;
	char pid[16];
	char sbuf[STRERR_BUFSIZE];
	struct perf_evlist *evlist;

	struct parse_events_evlist parse_evlist;
	struct parse_events_error parse_error;

	bzero(&parse_error, sizeof(parse_error));
	bzero(&parse_evlist, sizeof(parse_evlist));
	parse_evlist.error = &parse_error;
	INIT_LIST_HEAD(&parse_evlist.list);

	err = parse_events_load_bpf_obj(&parse_evlist, &parse_evlist.list, obj);
	if (err || list_empty(&parse_evlist.list)) {
		fprintf(stderr, " (Failed to add events selected by BPF)");
		if (!err)
			err = -EINVAL;
		goto out;
	}

	snprintf(pid, sizeof(pid), "%d", getpid());
	pid[sizeof(pid) - 1] = '\0';
	opts.target.tid = opts.target.pid = pid;

	/* Instead of perf_evlist__new_default, don't add default events */
	evlist = perf_evlist__new();
	if (!evlist) {
		pr_debug("No ehough memory to create evlist\n");
		return -ENOMEM;
	}

	err = perf_evlist__create_maps(evlist, &opts.target);
	if (err < 0) {
		pr_debug("Not enough memory to create thread/cpu maps\n");
		goto out_delete_evlist;
	}

	perf_evlist__splice_list_tail(evlist, &parse_evlist.list);
	evlist->nr_groups = parse_evlist.nr_groups;

	perf_evlist__config(evlist, &opts);

	err = perf_evlist__open(evlist);
	if (err < 0) {
		pr_debug("perf_evlist__open: %s\n",
			 strerror_r(errno, sbuf, sizeof(sbuf)));
		goto out_delete_evlist;
	}

	err = perf_evlist__mmap(evlist, opts.mmap_pages, false);
	if (err < 0) {
		pr_debug("perf_evlist__mmap: %s\n",
			 strerror_r(errno, sbuf, sizeof(sbuf)));
		goto out_delete_evlist;
	}

	perf_evlist__enable(evlist);
	(*func)();
	perf_evlist__disable(evlist);

	for (i = 0; i < evlist->nr_mmaps; i++) {
		union perf_event *event;

		while ((event = perf_evlist__mmap_read(evlist, i)) != NULL) {
			const u32 type = event->header.type;

			if (type == PERF_RECORD_SAMPLE)
				count ++;
		}
	}

	if (count != expect) {
		fprintf(stderr, " (filter result incorrect: %d != %d)", count, expect);
		err = -EBADF;
	}

out_delete_evlist:
	perf_evlist__delete(evlist);
out:
	if (err)
		return TEST_FAIL;
	return 0;
}

static int __test__bpf(int index, const char *name,
		       const char *message_compile,
		       const char *message_load,
		       int (*func)(void), int expect)
{
	int err;
	void *obj_buf;
	size_t obj_buf_sz;
	struct bpf_object *obj;

	test_llvm__fetch_bpf_obj(&obj_buf, &obj_buf_sz, index);
	if (!obj_buf || !obj_buf_sz) {
		if (verbose == 0)
			fprintf(stderr, " (%s)", message_compile);
		return TEST_SKIP;
	}

	obj = prepare_bpf(name, obj_buf, obj_buf_sz);
	if (!obj) {
		err = -EINVAL;
		if ((verbose == 0) && (message_load[0] != '\0'))
			fprintf(stderr, " (%s)", message_load);
		goto out;
	}

	err = do_test(obj, func, expect);
	if (err)
		goto out;
out:
	bpf__clear();
	if (err)
		return TEST_FAIL;
	return 0;
}

int test__bpf(void)
{
	int err;

	if (geteuid() != 0) {
		fprintf(stderr, " (try run as root)");
		return TEST_SKIP;
	}

	err = __test__bpf(LLVM_TESTCASE_BASE,
			  "[basic_bpf_test]",
			  "fix 'perf test LLVM' first",
			  "load bpf object failed",
			  &epoll_pwait_loop,
			  (NR_ITERS + 1) / 2);
	if (err)
		return err;

#ifdef HAVE_BPF_PROLOGUE
	err = __test__bpf(LLVM_TESTCASE_BPF_PROLOGUE,
			  "[bpf_prologue_test]",
			  "fix kbuild first",
			  "check your vmlinux setting?",
			  &llseek_loop,
			  (NR_ITERS + 1) / 4);
	return err;
#else
	fprintf(stderr, " (skip BPF prologue test)");
	return TEST_OK;
#endif
}

#else
int test__bpf(void)
{
	return TEST_SKIP;
}
#endif
