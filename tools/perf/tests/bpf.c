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

static int prepare_bpf(void *obj_buf, size_t obj_buf_sz)
{
	int err;
	char errbuf[BUFSIZ];

	err = bpf__prepare_load_buffer(obj_buf, obj_buf_sz);
	if (err) {
		bpf__strerror_prepare_load("[buffer]", false, err, errbuf,
					   sizeof(errbuf));
		fprintf(stderr, " (%s)", errbuf);
		return TEST_FAIL;
	}

	err = bpf__probe();
	if (err) {
		bpf__strerror_load(err, errbuf, sizeof(errbuf));
		fprintf(stderr, " (%s)", errbuf);
		if (getuid() != 0)
			fprintf(stderr, " (try run as root)");
		return TEST_FAIL;
	}

	err = bpf__load();
	if (err) {
		bpf__strerror_load(err, errbuf, sizeof(errbuf));
		fprintf(stderr, " (%s)", errbuf);
		return TEST_FAIL;
	}

	return 0;
}

static int do_test(void)
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

	int err, i, count = 0;
	char pid[16];
	char sbuf[STRERR_BUFSIZE];
	struct perf_evlist *evlist;

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

	err = perf_evlist__add_bpf(evlist);
	if (err) {
		fprintf(stderr, " (Failed to add events selected by BPF)");
		goto out_delete_evlist;
	}

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
	epoll_pwait_loop();
	perf_evlist__disable(evlist);

	for (i = 0; i < evlist->nr_mmaps; i++) {
		union perf_event *event;

		while ((event = perf_evlist__mmap_read(evlist, i)) != NULL) {
			const u32 type = event->header.type;

			if (type == PERF_RECORD_SAMPLE)
				count ++;
		}
	}

	if (count != (NR_ITERS + 1) / 2) {
		fprintf(stderr, " (filter result incorrect)");
		err = -EBADF;
	}

out_delete_evlist:
	perf_evlist__delete(evlist);
	if (err)
		return TEST_FAIL;
	return 0;
}

int test__bpf(void)
{
	int err;
	void *obj_buf;
	size_t obj_buf_sz;

	test_llvm__fetch_bpf_obj(&obj_buf, &obj_buf_sz);
	if (!obj_buf || !obj_buf_sz) {
		if (verbose == 0)
			fprintf(stderr, " (fix 'perf test LLVM' first)");
		return TEST_SKIP;
	}

	err = prepare_bpf(obj_buf, obj_buf_sz);
	if (err)
		goto out;

	err = do_test();
	if (err)
		goto out;
out:
	bpf__unprobe();
	bpf__clear();
	if (err)
		return TEST_FAIL;
	return 0;
}

#else
int test__bpf(void)
{
	return TEST_SKIP;
}
#endif
