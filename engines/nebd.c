/*
 * Copyright (c) 2021 NetEase Inc.
 *
 * nebd engine
 *
 * IO engine using nebdclient to test NEBD Block Devices.
 *
 */

/*
 * Project: nebd
 * File Created: 2021-11-5
 * Author: yfxu
 */

#include "../fio.h"
#include "../optgroup.h"

#include <semaphore.h>
#include <sys/queue.h>
#include <nebd/libnebd.h>

struct fio_nebd_iou {
	struct NebdClientAioContext io_ctx;
	struct io_u *io_u;
	TAILQ_ENTRY(fio_nebd_iou) link;
	struct nebd_data *nebd;
};

struct nebd_global {
	bool inited;	// lib inited
};

struct nebd_stat {
	int fd;
	int open;	    // open count
	char *filename;
	TAILQ_ENTRY(nebd_stat) link;
};

struct nebd_data {
	struct io_u **aio_events;
	struct nebd_stat *st;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	TAILQ_HEAD(, fio_nebd_iou) completed;
	int inflight;
};

struct nebd_options {
	void *pad;
	char *nebd_name;
	char *conf_name;
	int busy_poll;
};

static pthread_mutex_t nebd_stat_mutex = PTHREAD_MUTEX_INITIALIZER;
static TAILQ_HEAD(nebd_list, nebd_stat) all_nebd = TAILQ_HEAD_INITIALIZER(all_nebd);

static struct nebd_global nebd_global;

static struct fio_option options[] = {
	{
		.name		= "nebd",
		.lname		= "nebd",
		.type		= FIO_OPT_STR_STORE,
		.help		= "NEBD name for nebd engine",
		.off1		= offsetof(struct nebd_options, nebd_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name		= "conf",
		.lname		= "conf",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of config file for the nebd engine",
		.off1		= offsetof(struct nebd_options, conf_name),
		.def		= "/etc/nebd/nebd-client.conf",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name		= "busy_poll",
		.lname		= "busy_poll",
		.type		= FIO_OPT_BOOL,
		.help		= "Busy poll for completions instead of sleeping",
		.off1		= offsetof(struct nebd_options, busy_poll),
		.def		= "0",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name = NULL,
	},
};

static struct nebd_stat *_fio_find_nebd_stat(const char *filename)
{
	struct nebd_stat *st;

	TAILQ_FOREACH(st, &all_nebd, link) {
		if (!strcmp(filename, st->filename))
			return st;
	}

	return st;
}

static struct nebd_stat *_fio_alloc_nebd_stat(const char *filename)
{
	struct nebd_stat *st;

	st = calloc(1, sizeof(*st));
	if (st) {
		st->filename = strdup(filename);
		if (st->filename == NULL) {
			free(st);
			return NULL;
		}

		st->fd = -1;
	}

	return st;
}

static void _fio_free_nebd_stat(struct nebd_stat *st)
{
	free(st->filename);
	free(st);
}

static void _fio_add_nebd_stat(struct nebd_stat *st)
{
	TAILQ_INSERT_HEAD(&all_nebd, st, link);
}

static void _fio_remove_nebd_stat(struct nebd_stat *st)
{
	TAILQ_REMOVE(&all_nebd, st, link);
}

static int _fio_setup_nebd_data(struct thread_data *td,
			        struct nebd_data **nebd_data_ptr)
{
	struct nebd_data *nebd;
	//struct nebd_options *o = td->eo;

	if (td->io_ops_data)
		return 0;

	nebd = calloc(1, sizeof(struct nebd_data));
	if (!nebd)
		goto failed;

	nebd->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!nebd->aio_events)
		goto failed;

	TAILQ_INIT(&nebd->completed);
	pthread_mutex_init(&nebd->mutex, NULL);
	pthread_cond_init(&nebd->cond, NULL);
	nebd->inflight = 0;
	*nebd_data_ptr = nebd;
	return 0;

failed:
	if (nebd) {
		free(nebd->aio_events);
		free(nebd);
	}
	return 1;
}

static int _fio_nebd_connect(struct thread_data *td)
{
	struct nebd_data *nebd = td->io_ops_data;
	struct nebd_stat *st;
	struct nebd_options *o = td->eo;
	int r;

	if (nebd->st)
		return 0;

	pthread_mutex_lock(&nebd_stat_mutex);
	if (!nebd_global.inited) {
		if (nebd_lib_init()){
			pthread_mutex_unlock(&nebd_stat_mutex);
			log_err("nebd_lib_init failed.\n");
			return 1;
		} else {
			nebd_global.inited = true;
		}
	}

	st = _fio_find_nebd_stat(o->nebd_name);
	if (st == NULL) {
		st = _fio_alloc_nebd_stat(o->nebd_name);
		if (st == NULL) {
			pthread_mutex_unlock(&nebd_stat_mutex);
			log_err("not enough memory.\n");
			return 1;
		}
		r = nebd_lib_open(st->filename);
		if (r < 0) {
			pthread_mutex_unlock(&nebd_stat_mutex);
			log_err("nebd_lib_open %s failed.\n", st->filename);
			_fio_free_nebd_stat(st);
			return 1;
		}

		st->fd = r;
		_fio_add_nebd_stat(st);
		log_info("open nebd %s, fd=%d\n", o->nebd_name, st->fd);
	}
	st->open++;
	nebd->st = st;
	pthread_mutex_unlock(&nebd_stat_mutex);

	return 0;
}

static void _fio_nebd_disconnect(struct nebd_data *nebd)
{
	if (!nebd)
		return;

	if (!nebd->st)
		return;

	pthread_mutex_lock(&nebd_stat_mutex);
	nebd->st->open--;
	if (!nebd->st->open) {
		nebd_lib_close(nebd->st->fd);
		_fio_remove_nebd_stat(nebd->st);
		_fio_free_nebd_stat(nebd->st);
	}
	pthread_mutex_unlock(&nebd_stat_mutex);
	nebd->st = NULL;
}

static void _fio_nebd_finish_aiocb(struct NebdClientAioContext* context)
{
	struct fio_nebd_iou *fni = (struct fio_nebd_iou *)context;
	struct nebd_data *nebd = fni->nebd;
	struct io_u *io_u = fni->io_u;
	ssize_t ret;

	/*
	 * Looks like return value is 0 for success, or < 0 for
	 * a specific error. So we have to assume that it can't do
	 * partial completions.
	 */
	ret = context->ret;
	if (ret < 0) {
		io_u->error = -EIO;
		io_u->resid = io_u->xfer_buflen;
	} else
		io_u->error = 0;

	pthread_mutex_lock(&nebd->mutex);
	TAILQ_INSERT_TAIL(&nebd->completed, fni, link);
	nebd->inflight--;
	pthread_cond_broadcast(&nebd->cond);
	pthread_mutex_unlock(&nebd->mutex);
}

static struct io_u *fio_nebd_event(struct thread_data *td, int event)
{
	struct nebd_data *nebd = td->io_ops_data;

	return nebd->aio_events[event];
}

static int nebd_iter_events(struct thread_data *td, unsigned int *events,
			   unsigned int min_evts, int wait)
{
	struct nebd_data *nebd = td->io_ops_data;
	TAILQ_HEAD(, fio_nebd_iou) list = TAILQ_HEAD_INITIALIZER(list);
	unsigned int this_events = 0;
	int inflight = 0;

	pthread_mutex_lock(&nebd->mutex);
again:
	TAILQ_CONCAT(&list, &nebd->completed, link);
	inflight = nebd->inflight;
	pthread_mutex_unlock(&nebd->mutex);

	while (!TAILQ_EMPTY(&list)) {
		struct fio_nebd_iou *fni = TAILQ_FIRST(&list);
		nebd->aio_events[*events] = fni->io_u;
		(*events)++;
		this_events++;
		TAILQ_REMOVE(&list, fni, link);
	}

	if (!wait || !inflight || *events >= min_evts)
		return this_events;

	pthread_mutex_lock(&nebd->mutex);
	while (TAILQ_EMPTY(&nebd->completed) && nebd->inflight)
		pthread_cond_wait(&nebd->cond, &nebd->mutex);
	goto again;
}

static int fio_nebd_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max, const struct timespec *t)
{
	unsigned int this_events, events = 0;
	struct nebd_options *o = td->eo;
	int wait = 0;

	do {
		this_events = nebd_iter_events(td, &events, min, wait);

		if (events >= min)
			break;
		if (this_events)
			continue;

		if (!o->busy_poll)
			wait = 1;
		else
			nop;
	} while (1);

	return events;
}

static enum fio_q_status fio_nebd_queue(struct thread_data *td,
				        struct io_u *io_u)
{
	struct nebd_data *nebd = td->io_ops_data;
	struct fio_nebd_iou *fni = io_u->engine_data;
	int fd = nebd->st->fd;
	int r = -1;

	fio_ro_check(td, io_u);

	pthread_mutex_lock(&nebd->mutex);
	nebd->inflight++;
	pthread_mutex_unlock(&nebd->mutex);
	fni->nebd = nebd;

	fni->io_ctx.offset = io_u->offset;
	fni->io_ctx.length = io_u->xfer_buflen;
	fni->io_ctx.buf = io_u->xfer_buf;
	fni->io_ctx.ret = -1;
	fni->io_ctx.cb = _fio_nebd_finish_aiocb;
	fni->io_ctx.retryCount = 0;
	
	if (io_u->ddir == DDIR_WRITE) {
		fni->io_ctx.op = LIBAIO_OP_WRITE;
		r = nebd_lib_aio_pwrite(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("nebd_lib_aio_pwrite failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_READ) {
		fni->io_ctx.op = LIBAIO_OP_READ;
		r = nebd_lib_aio_pread(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("nebd_lib_aio_pread failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_TRIM) {
		fni->io_ctx.op = LIBAIO_OP_DISCARD;
		r = nebd_lib_discard(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("nebd_lib_discard failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_SYNC) {
		fni->io_ctx.op = LIBAIO_OP_FLUSH;
		r = nebd_lib_flush(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("nebd_lib_flush failed.\n");
			goto failed_comp;
		}
	} else {
		dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
		       io_u->ddir);
		r = -EINVAL;
		goto failed_comp;
	}

	return FIO_Q_QUEUED;
failed_comp:
	io_u->error = -EIO;
	td_verror(td, io_u->error, "xfer");
	pthread_mutex_lock(&nebd->mutex);
	nebd->inflight--;
	pthread_cond_broadcast(&nebd->cond);
	pthread_mutex_unlock(&nebd->mutex);

	return FIO_Q_COMPLETED;
}

static int fio_nebd_init(struct thread_data *td)
{
	int r;
	struct nebd_data *nebd = td->io_ops_data;

	if (nebd->st)
		return 0;

	r = _fio_nebd_connect(td);
	if (r) {
		log_err("fio_nebd_connect failed, return code: %d .\n", r);
		goto failed;
	}

	return 0;

failed:
	return 1;
}

static void fio_nebd_cleanup(struct thread_data *td)
{
	struct nebd_data *nebd = td->io_ops_data;

	if (nebd) {
		_fio_nebd_disconnect(nebd);
		pthread_mutex_destroy(&nebd->mutex);
		pthread_cond_destroy(&nebd->cond);
		free(nebd->aio_events);
		free(nebd);
	}
}

static int fio_nebd_setup(struct thread_data *td)
{
	struct fio_file *f;
	struct nebd_data *nebd = NULL;
	int r;
	size_t size;

	/* allocate engine specific structure to deal with libnebdclient. */
	r = _fio_setup_nebd_data(td, &nebd);
	if (r) {
		log_err("fio_setup_nebd_data failed.\n");
		goto cleanup;
	}
	td->io_ops_data = nebd;

	/* libnebdclient does not allow us to run first in the main thread and later
	 * in a fork child. It needs to be the same process context all the
	 * time. 
	 */
	td->o.use_thread = 1;

	/* connect in the main thread to determine to determine
	 * the size of the given RADOS block device. And disconnect
	 * later on.
	 */
	r = _fio_nebd_connect(td);
	if (r) {
		log_err("fio_nebd_connect failed.\n");
		goto cleanup;
	}

	size = nebd_lib_filesize(nebd->st->fd);

	/* get size of the RADOS block device */
	if (size < 0) {
		log_err("nebd_lib_filesize failed.\n");
		goto cleanup;
	} else if (size == 0) {
		log_err("image size should be larger than zero.\n");
		r = -EINVAL;
		goto cleanup;
	}

	dprint(FD_IO, "nebd-engine: image size: %" PRIu64 "\n", size);

	/* taken from "net" engine. Pretend we deal with files,
	 * even if we do not have any ideas about files.
	 * The size of the RBD is set instead of a artificial file.
	 */
	if (!td->files_index) {
		add_file(td, td->o.filename ? : "nebd", 0, 0);
		td->o.nr_files = td->o.nr_files ? : 1;
		td->o.open_files++;
	}
	f = td->files[0];
	f->real_file_size = size;

	return 0;

cleanup:
	fio_nebd_cleanup(td);
	return r;
}

static int fio_nebd_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_nebd_invalidate(struct thread_data *td, struct fio_file *f)
{
#if defined(CONFIG_NEBD_INVAL)
	struct nebd_data *nebd = td->io_ops_data;
	return nebd_lib_invalidcache(nebd_stat.fd);
#else
	return 0;
#endif
}

static void fio_nebd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_nebd_iou *fni = io_u->engine_data;

	if (fni) {
		io_u->engine_data = NULL;
		free(fni);
	}
}

static int fio_nebd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_nebd_iou *fni;

	fni = calloc(1, sizeof(*fni));
	fni->io_u = io_u;
	io_u->engine_data = fni;
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "nebd",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_nebd_setup,
	.init			= fio_nebd_init,
	.queue			= fio_nebd_queue,
	.getevents		= fio_nebd_getevents,
	.event			= fio_nebd_event,
	.cleanup		= fio_nebd_cleanup,
	.open_file		= fio_nebd_open,
	.invalidate		= fio_nebd_invalidate,
	.options		= options,
	.io_u_init		= fio_nebd_io_u_init,
	.io_u_free		= fio_nebd_io_u_free,
	.flags			= FIO_NOFILEHASH|FIO_DISKLESSIO|FIO_NODISKUTIL,
	.option_struct_size	= sizeof(struct nebd_options),
};

static void fio_init fio_nebd_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_nebd_unregister(void)
{
	unregister_ioengine(&ioengine);
}

