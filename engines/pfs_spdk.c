/*
 * pfs spdk engine
 *
 * IO engine that does regular pfs_pread(2)/pfs_pwrite(2) to transfer data.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pfs_option_api.h>
#include <pfs_spdk_api.h>
#include <pfsd.h>
#include <pfs_api.h>

#include "../fio.h"
#include "../optgroup.h"
#include "../lib/rand.h"

/*
 * Sync engine uses engine_data to store last offset
 */
#define LAST_POS(f) ((f)->engine_pos)


struct pfs_options {
    void *pad;
    char *cluster;
    char *pbd;
    int hostid;
    char *config_path;
    char *spdk_nvme_controller;
    char *spdk_env_context;
};

static struct fio_option options[] = {
    {
        .name     = "cluster",
        .lname    = "cluster",
        .type     = FIO_OPT_STR_STORE,
        .help     = "cluster type",
        .off1     = offsetof(struct pfs_options, cluster),
        .def      = "spdk",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = "pbd",
        .lname    = "pbd",
        .type     = FIO_OPT_STR_STORE,
        .help     = "pbd name",
        .off1     = offsetof(struct pfs_options, pbd),
        .def      = NULL,
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = "host",
        .lname    = "host",
        .type     = FIO_OPT_INT,
        .help     = "paxos host id",
        .off1     = offsetof(struct pfs_options, hostid),
        .def      = "1",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = "config_path",
        .lname    = "config_path",
        .type     = FIO_OPT_STR_STORE,
        .help     = "pfs config path",
        .off1     = offsetof(struct pfs_options, config_path),
        .def      = NULL,
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = "spdk_nvme_controller",
        .lname    = "spdk_nvme_controller",
        .type     = FIO_OPT_STR_STORE,
        .help     = "spdk nvme controller",
        .off1     = offsetof(struct pfs_options, spdk_nvme_controller),
        .def      = NULL,
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = "spdk_env_context",
        .lname    = "spdk_env_context",
        .type     = FIO_OPT_STR_STORE,
        .help     = "spdk env context",
        .off1     = offsetof(struct pfs_options, spdk_env_context),
        .def      = NULL,
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS_SPDK,
    },
    {
        .name     = NULL,
    },
};

static pthread_mutex_t pfs_mount_lock = PTHREAD_MUTEX_INITIALIZER;
struct pfs_data {
    int pfs_mounted;
    char pbd[1024];
    int hostid;
};

static struct pfs_data pfs_data;

static int fio_pfs_file_size(struct thread_data *td, struct fio_file *f);

static int fio_pfs_connect(struct thread_data *td)
{
    struct pfs_options *o = td->eo;
    int ret;

    pthread_mutex_lock(&pfs_mount_lock);
    if (pfs_data.pfs_mounted) {
        pthread_mutex_unlock(&pfs_mount_lock);
        return 0;
    }
    if (o->config_path != NULL) {
        ret = pfs_option_init(o->config_path);
        if (ret) {
            pthread_mutex_unlock(&pfs_mount_lock);
            log_err("pfs_option_init fail, ret: %d\n", ret);
            return 1;
        }
    }
    if (o->spdk_nvme_controller != NULL) {
        ret = pfs_option_set("spdk_nvme_controller", o->spdk_nvme_controller);
        if (ret) {
            pthread_mutex_unlock(&pfs_mount_lock);
            log_err("pfs_option_set spdk_nvme_controller fail, ret: %d\n", ret);
            return 1;
        }
    }
    if (o->spdk_env_context != NULL) {
        ret = pfs_option_set("spdk_env_context", o->spdk_env_context);
        if (ret) {
            pthread_mutex_unlock(&pfs_mount_lock);
            log_err("pfs_option_set spdk_env_context fail, ret: %d\n", ret);
            return 1;
        }
    }
    if (o->pbd == NULL) {
        log_err("pbdname not set!");
        return 1;
    }
    ret = pfs_option_set("pbd_name", o->pbd);
    if (ret) {
        pthread_mutex_unlock(&pfs_mount_lock);
        log_err("pfs_option_set pbdname fail, ret: %d\n", ret);
        return 1;
    }
    ret = pfs_spdk_setup();
    if (ret) {
        log_err("pfs_spdk_setup fail, ret: %d\n", ret);
        return 1;
    }
    ret = pfsd_start(true);
    if (ret) {
        log_err("pfsd_start fail, ret: %d\n", ret);
        return 1;
    }
    ret = pfs_mount_acquire(o->cluster, o->pbd, o->hostid,
        PFS_RDWR);
    if (ret) {
        pthread_mutex_unlock(&pfs_mount_lock);
        log_err("pfs_mount_acquire fail, ret: %d\n", ret);
        return 1;
    }
    pfs_data.pfs_mounted = 1;
    strcpy(pfs_data.pbd, o->pbd);
    pfs_data.hostid = o->hostid;
    pthread_mutex_unlock(&pfs_mount_lock);
    return 0;
}

static void fio_pfs_disconnect(void)
{
    pthread_mutex_lock(&pfs_mount_lock);
    if (pfs_data.pfs_mounted)
        pfs_mount_release(pfs_data.pbd, pfs_data.hostid);
    pfs_data.pfs_mounted = 0;
    pthread_mutex_unlock(&pfs_mount_lock);
}

static int fio_io_end(struct thread_data *td, struct io_u *io_u, int ret)
{
    if (ret != (ssize_t) io_u->xfer_buflen) {
        if (ret >= 0) {
            io_u->resid = io_u->xfer_buflen - ret;
            io_u->error = 0;
            return FIO_Q_COMPLETED;
        } else
            io_u->error = errno;
    }

    if (io_u->error) {
        io_u_log_error(td, io_u);
        td_verror(td, io_u->error, "xfer");
    }

    return FIO_Q_COMPLETED;
}

static enum fio_q_status fio_pfs_queue(struct thread_data *td,
        struct io_u *io_u)
{
    struct fio_file *f = io_u->file;
    int ret;

    fio_ro_check(td, io_u);

    if (io_u->ddir == DDIR_READ)
        ret = pfs_pread_dma(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
    else if (io_u->ddir == DDIR_WRITE)
        ret = pfs_pwrite_dma(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
    else if (io_u->ddir == DDIR_SYNC)
        ret = pfs_fsync(f->fd);
    else {
        ret = io_u->xfer_buflen;
        io_u->error = EINVAL;
    }

    return fio_io_end(td, io_u, ret);
}

static int fio_pfs_setup(struct thread_data *td)
{
    td->o.use_thread = 1;
    return 0;
}

static int fio_pfs_init(struct thread_data *td)
{
    return fio_pfs_connect(td);
}

static void fio_pfs_cleanup(struct thread_data *td)
{
/*
    int ret;
    ret = pfsd_stop();
    if (ret) {
        log_err("pfsd_stop fail, ret: %d\n", ret);
    }
*/
}

static int fio_pfs_open_file(struct thread_data *td, struct fio_file *f)
{
    int flags = 0;
    int ret;
	uint64_t desired_fs;

    if (td->o.create_on_open && td->o.allow_create)
        flags |= O_CREAT;

    if (td_trim(td)) {
        td_verror(td, EINVAL, "pfs does not support trim");
        return 1;
    }

    if (td->o.oatomic) {
        td_verror(td, EINVAL, "pfs does not support atomic IO");
        return 1;
    }

    if (td->o.create_on_open && td->o.allow_create)
        flags |= O_CREAT;

    if (td_write(td)) {
        if (!read_only)
            flags |= O_RDWR;

        if (td->o.allow_create)
            flags |= O_CREAT;
    } else if (td_read(td)) {
        flags |= O_RDONLY;
    } else {
        /* We should never go here. */
        td_verror(td, EINVAL, "Unsopported open mode");
        return 1;
    }

    f->fd = pfs_open(f->file_name, flags, 0600);
    if (f->fd == -1) {
        char buf[FIO_VERROR_SIZE];
        int __e = errno;

        snprintf(buf, sizeof(buf), "pfs_open(%s)", f->file_name);
        td_verror(td, __e, buf);
        return 1;
    }

    /* Now we need to make sure the real file size is sufficient for FIO
       to do its things. This is normally done before the file open function
       is called, but because FIO would use POSIX calls, we need to do it
       ourselves */
    ret = fio_pfs_file_size(td, f);
    if (ret) {
        pfs_close(f->fd);
        td_verror(td, errno, "fio_pfs_file_size");
        return 1;
    }

    desired_fs = f->io_size + f->file_offset;
    if (td_write(td)) {
        dprint(FD_FILE, "Laying out file %s\n", f->file_name);
        if (!td->o.create_on_open &&
                f->real_file_size < desired_fs &&
                pfs_ftruncate(f->fd, desired_fs) < 0) {
            pfs_close(f->fd);
            td_verror(td, errno, "pfs_ftruncate");
            return 1;
        }
        if (f->real_file_size < desired_fs)
            f->real_file_size = desired_fs;
    } else if (td_read(td) && f->real_file_size < desired_fs) {
        pfs_close(f->fd);
        log_err("error: can't read %lu bytes from file with "
                        "%lu bytes\n", desired_fs, f->real_file_size);
        return 1;
    }

    f->filetype = FIO_TYPE_FILE;

    return 0;
}

static int fio_pfs_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
    int ret = 0;

    if (pfs_close(f->fd) < 0)
        ret = errno;

    f->fd = -1;
    return ret;
}

static int fio_pfs_invalidate_cache(struct thread_data *td, struct fio_file *f)
{
    return 0;
}

static int fio_pfs_unlink_file(struct thread_data *td, struct fio_file *f)
{
    int ret;

    ret = pfs_unlink(f->file_name);
    return ret < 0 ? errno : 0;
}

static int fio_pfs_file_size(struct thread_data *td, struct fio_file *f)
{
    struct stat st;

    if (fio_pfs_connect(td))
        return 1;

    if (pfs_stat(f->file_name, &st) == -1) {
        td_verror(td, errno, "pfs_stat");
        return 1;
    }

    f->real_file_size = st.st_size;
    return 0;
}

static struct ioengine_ops ioengine_prw = {
    .name       = "pfs_spdk",
    .version    = FIO_IOOPS_VERSION,
    .setup      = fio_pfs_setup,
    .init       = fio_pfs_init,
    .cleanup    = fio_pfs_cleanup,
    .queue      = fio_pfs_queue,
    .open_file  = fio_pfs_open_file,
    .close_file = fio_pfs_close_file,
    .invalidate = fio_pfs_invalidate_cache,
    .get_file_size  = fio_pfs_file_size,
    .unlink_file = fio_pfs_unlink_file,
    .flags      = FIO_SYNCIO|FIO_NOFILEHASH|FIO_DISKLESSIO|FIO_NODISKUTIL,
    .options    = options,
    .option_struct_size = sizeof(struct pfs_options),
};

static void fio_init fio_pfs_register(void)
{
    register_ioengine(&ioengine_prw);
}

static void fio_exit fio_pfs_unregister(void)
{
    int ret;

    fio_pfs_disconnect();
    ret = pfsd_stop();
    if (ret) {
        log_err("pfsd_stop fail, ret: %d\n", ret);
    }
    pfsd_wait_stop();
    pfs_spdk_cleanup();
    unregister_ioengine(&ioengine_prw);
}
