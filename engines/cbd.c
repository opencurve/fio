/*
 * Copyright (c) 2022 NetEase Inc.
 *
 * curve block device engine
 *
 * IO engine using curve client to test Curve Block Devices.
 *
 */

/*
 * Project: curve
 * File Created: 2022-04-28
 * Author: xuchaojie
 */

#include "../fio.h"
#include "../optgroup.h"

#include <semaphore.h>
#include <sys/queue.h>
#include <libcbd.h>

struct fio_cbd_iou {
	struct CurveAioContext io_ctx;
	struct io_u *io_u;
	TAILQ_ENTRY(fio_cbd_iou) link;
	struct cbd_data *cbd;
};

struct cbd_stat {
	int fd;
	int open;	    // open count
	char *filename;
	TAILQ_ENTRY(cbd_stat) link;
};

struct cbd_data {
	struct io_u **aio_events;
	struct cbd_stat *st;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	TAILQ_HEAD(, fio_cbd_iou) completed;
	int inflight;
};

struct cbd_options {
	void *pad;
	char *cbd_name;
	char *conf_name;
	int busy_poll;
};

static pthread_mutex_t cbd_stat_mutex = PTHREAD_MUTEX_INITIALIZER;
static TAILQ_HEAD(cbd_list, cbd_stat) all_cbd = TAILQ_HEAD_INITIALIZER(all_cbd);

static struct CurveOptions cbd_global;

static struct fio_option options[] = {
	{
		.name		= "cbd",
		.lname		= "cbd",
		.type		= FIO_OPT_STR_STORE,
		.help		= "engine name for cbd engine",
		.off1		= offsetof(struct cbd_options, cbd_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name		= "conf",
		.lname		= "conf",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of config file for the cbd engine",
		.off1		= offsetof(struct cbd_options, conf_name),
		.def		= "/etc/curve/client.conf",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name		= "busy_poll",
		.lname		= "busy_poll",
		.type		= FIO_OPT_BOOL,
		.help		= "Busy poll for completions instead of sleeping",
		.off1		= offsetof(struct cbd_options, busy_poll),
		.def		= "0",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_NEBD,
	},
	{
		.name = NULL,
	},
};

static struct cbd_stat *_fio_find_cbd_stat(const char *filename)
{
	struct cbd_stat *st;

	TAILQ_FOREACH(st, &all_cbd, link) {
		if (!strcmp(filename, st->filename))
			return st;
	}

	return st;
}

static struct cbd_stat *_fio_alloc_cbd_stat(const char *filename)
{
	struct cbd_stat *st;

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

static void _fio_free_cbd_stat(struct cbd_stat *st)
{
	free(st->filename);
	free(st);
}

static void _fio_add_cbd_stat(struct cbd_stat *st)
{
	TAILQ_INSERT_HEAD(&all_cbd, st, link);
}

static void _fio_remove_cbd_stat(struct cbd_stat *st)
{
	TAILQ_REMOVE(&all_cbd, st, link);
}

static int _fio_setup_cbd_data(struct thread_data *td,
			        struct cbd_data **cbd_data_ptr)
{
	struct cbd_data *cbd;
	//struct cbd_options *o = td->eo;

	if (td->io_ops_data)
		return 0;

	cbd = calloc(1, sizeof(struct cbd_data));
	if (!cbd)
		goto failed;

	cbd->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!cbd->aio_events)
		goto failed;

	TAILQ_INIT(&cbd->completed);
	pthread_mutex_init(&cbd->mutex, NULL);
	pthread_cond_init(&cbd->cond, NULL);
	cbd->inflight = 0;
	*cbd_data_ptr = cbd;
	return 0;

failed:
	if (cbd) {
		free(cbd->aio_events);
		free(cbd);
	}
	return 1;
}

static int _fio_cbd_connect(struct thread_data *td)
{
	struct cbd_data *cbd = td->io_ops_data;
	struct cbd_stat *st;
	struct cbd_options *o = td->eo;
	int r;

	if (cbd->st)
		return 0;

	pthread_mutex_lock(&cbd_stat_mutex);
	if (!cbd_global.inited) {
        cbd_global.conf = o->conf_name;
        r = cbd_libcurve_init(&cbd_global);
		if (r < 0) {
			pthread_mutex_unlock(&cbd_stat_mutex);
			log_err("cbd Init failed, r=%d, conf name=%s\n", r, o->conf_name);
			return 1;
		} else {
			cbd_global.inited = true;
		}
	}

	st = _fio_find_cbd_stat(o->cbd_name);
	if (st == NULL) {
		st = _fio_alloc_cbd_stat(o->cbd_name);
		if (st == NULL) {
			pthread_mutex_unlock(&cbd_stat_mutex);
			log_err("not enough memory.\n");
			return 1;
		}
		r = cbd_libcurve_open(st->filename);
		if (r < 0) {
			pthread_mutex_unlock(&cbd_stat_mutex);
			log_err("cbd open %s failed.\n", st->filename);
			_fio_free_cbd_stat(st);
			return 1;
		}

		st->fd = r;
		_fio_add_cbd_stat(st);
		log_info("cbd open %s, fd=%d\n", o->cbd_name, st->fd);
	}
	st->open++;
	cbd->st = st;
	pthread_mutex_unlock(&cbd_stat_mutex);

	return 0;
}

static void _fio_cbd_disconnect(struct cbd_data *cbd)
{
	if (!cbd)
		return;

	if (!cbd->st)
		return;

	pthread_mutex_lock(&cbd_stat_mutex);
	cbd->st->open--;
	if (!cbd->st->open) {
		cbd_libcurve_close(cbd->st->fd);
		_fio_remove_cbd_stat(cbd->st);
		_fio_free_cbd_stat(cbd->st);
	}
	pthread_mutex_unlock(&cbd_stat_mutex);
	cbd->st = NULL;
}

static void _fio_cbd_finish_aiocb(struct CurveAioContext* context)
{
	struct fio_cbd_iou *fni = (struct fio_cbd_iou *)context;
	struct cbd_data *cbd = fni->cbd;
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

	pthread_mutex_lock(&cbd->mutex);
	TAILQ_INSERT_TAIL(&cbd->completed, fni, link);
	cbd->inflight--;
	pthread_cond_broadcast(&cbd->cond);
	pthread_mutex_unlock(&cbd->mutex);
}

static struct io_u *fio_cbd_event(struct thread_data *td, int event)
{
	struct cbd_data *cbd = td->io_ops_data;

	return cbd->aio_events[event];
}

static int cbd_iter_events(struct thread_data *td, unsigned int *events,
			   unsigned int min_evts, int wait)
{
	struct cbd_data *cbd = td->io_ops_data;
	TAILQ_HEAD(, fio_cbd_iou) list = TAILQ_HEAD_INITIALIZER(list);
	unsigned int this_events = 0;
	int inflight = 0;

	pthread_mutex_lock(&cbd->mutex);
again:
	TAILQ_CONCAT(&list, &cbd->completed, link);
	inflight = cbd->inflight;
	pthread_mutex_unlock(&cbd->mutex);

	while (!TAILQ_EMPTY(&list)) {
		struct fio_cbd_iou *fni = TAILQ_FIRST(&list);
		cbd->aio_events[*events] = fni->io_u;
		(*events)++;
		this_events++;
		TAILQ_REMOVE(&list, fni, link);
	}

	if (!wait || !inflight || *events >= min_evts)
		return this_events;

	pthread_mutex_lock(&cbd->mutex);
	while (TAILQ_EMPTY(&cbd->completed) && cbd->inflight)
		pthread_cond_wait(&cbd->cond, &cbd->mutex);
	goto again;
}

static int fio_cbd_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max, const struct timespec *t)
{
	unsigned int this_events, events = 0;
	struct cbd_options *o = td->eo;
	int wait = 0;

	do {
		this_events = cbd_iter_events(td, &events, min, wait);

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

static enum fio_q_status fio_cbd_queue(struct thread_data *td,
				        struct io_u *io_u)
{
	struct cbd_data *cbd = td->io_ops_data;
	struct fio_cbd_iou *fni = io_u->engine_data;
	int fd = cbd->st->fd;
	int r = -1;

	fio_ro_check(td, io_u);

	pthread_mutex_lock(&cbd->mutex);
	cbd->inflight++;
	pthread_mutex_unlock(&cbd->mutex);
	fni->cbd = cbd;

	fni->io_ctx.offset = io_u->offset;
	fni->io_ctx.length = io_u->xfer_buflen;
	fni->io_ctx.buf = io_u->xfer_buf;
	fni->io_ctx.ret = -1;
	fni->io_ctx.cb = _fio_cbd_finish_aiocb;

	if (io_u->ddir == DDIR_WRITE) {
		fni->io_ctx.op = LIBCURVE_OP_WRITE;
		r = cbd_libcurve_aio_pwrite(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("cbd_libcurve_aio_pwrite failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_READ) {
		fni->io_ctx.op = LIBCURVE_OP_READ;
		r = cbd_libcurve_aio_pread(fd, &fni->io_ctx);
		if (r < 0) {
			log_err("cbd_libcurve_aio_pread failed.\n");
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
	pthread_mutex_lock(&cbd->mutex);
	cbd->inflight--;
	pthread_cond_broadcast(&cbd->cond);
	pthread_mutex_unlock(&cbd->mutex);

	return FIO_Q_COMPLETED;
}

static int fio_cbd_init(struct thread_data *td)
{
	int r;
	struct cbd_data *cbd = td->io_ops_data;

	if (cbd->st)
		return 0;

	r = _fio_cbd_connect(td);
	if (r) {
		log_err("fio_cbd_connect failed, return code: %d .\n", r);
		goto failed;
	}

	return 0;

failed:
	return 1;
}

static void fio_cbd_cleanup(struct thread_data *td)
{
	struct cbd_data *cbd = td->io_ops_data;

	if (cbd) {
		_fio_cbd_disconnect(cbd);
		pthread_mutex_destroy(&cbd->mutex);
		pthread_cond_destroy(&cbd->cond);
		free(cbd->aio_events);
		free(cbd);
	}
}

static int fio_cbd_setup(struct thread_data *td)
{
	struct fio_file *f;
	struct cbd_data *cbd = NULL;
	int r;
	int64_t size;

	r = _fio_setup_cbd_data(td, &cbd);
	if (r) {
		log_err("fio_setup_cbd_data failed.\n");
		goto cleanup;
	}
	td->io_ops_data = cbd;

	td->o.use_thread = 1;

	r = _fio_cbd_connect(td);
	if (r) {
		log_err("fio_cbd_connect failed.\n");
		goto cleanup;
	}


    size = cbd_libcurve_filesize(cbd->st->filename);

	if (size < 0) {
		log_err("cbd stat file failed.\n");
		r = -EINVAL;
		goto cleanup;
	} else if (size == 0) {
		log_err("image size should be larger than zero.\n");
		r = -EINVAL;
		goto cleanup;
	}

	dprint(FD_IO, "cbd-engine: image size: %" PRIu64 "\n", size);

	if (!td->files_index) {
		add_file(td, td->o.filename ? : "cbd", 0, 0);
		td->o.nr_files = td->o.nr_files ? : 1;
		td->o.open_files++;
	}
	f = td->files[0];
	f->real_file_size = size;

	return 0;

cleanup:
	fio_cbd_cleanup(td);
	return r;
}

static int fio_cbd_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_cbd_invalidate(struct thread_data *td, struct fio_file *f)
{
#if defined(CONFIG_NEBD_INVAL)
	struct cbd_data *cbd = td->io_ops_data;
	return cbd_lib_invalidcache(cbd_stat.fd);
#else
	return 0;
#endif
}

static void fio_cbd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_cbd_iou *fni = io_u->engine_data;

	if (fni) {
		io_u->engine_data = NULL;
		free(fni);
	}
}

static int fio_cbd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_cbd_iou *fni;

	fni = calloc(1, sizeof(*fni));
	fni->io_u = io_u;
	io_u->engine_data = fni;
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "cbd",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_cbd_setup,
	.init			= fio_cbd_init,
	.queue			= fio_cbd_queue,
	.getevents		= fio_cbd_getevents,
	.event			= fio_cbd_event,
	.cleanup		= fio_cbd_cleanup,
	.open_file		= fio_cbd_open,
	.invalidate		= fio_cbd_invalidate,
	.options		= options,
	.io_u_init		= fio_cbd_io_u_init,
	.io_u_free		= fio_cbd_io_u_free,
	.flags			= FIO_NOFILEHASH|FIO_DISKLESSIO|FIO_NODISKUTIL,
	.option_struct_size	= sizeof(struct cbd_options),
};

static void fio_init fio_cbd_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cbd_unregister(void)
{
	unregister_ioengine(&ioengine);
}

