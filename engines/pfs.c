/*
 * pfs engine
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
#include <pfsd_sdk.h>

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
};

static struct fio_option options[] = {
    {
        .name     = "cluster",
        .lname    = "cluster",
        .type     = FIO_OPT_STR_STORE,
        .help     = "cluster type",
        .off1     = offsetof(struct pfs_options, cluster),
        .def      = "disk",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS,
    },
    {
        .name     = "pbd",
        .lname    = "pbd",
        .type     = FIO_OPT_STR_STORE,
        .help     = "pbd name",
        .off1     = offsetof(struct pfs_options, pbd),
        .def      = "",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS,
    },
    {
        .name     = "host",
        .lname    = "host",
        .type     = FIO_OPT_INT,
        .help     = "paxos host id",
        .off1     = offsetof(struct pfs_options, hostid),
        .def      = "1",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_PFS,
    },
    {
        .name     = NULL,
    },
};

static pthread_mutex_t pfs_mount_lock = PTHREAD_MUTEX_INITIALIZER;
struct pfs_data {
    int pfs_mounted;
    char pbd[1024];
};

static struct pfs_data pfs_data;

static int fio_pfs_connect(struct thread_data *td)
{
    struct pfs_options *o = td->eo;
    int ret;

    pthread_mutex_lock(&pfs_mount_lock);
    if (pfs_data.pfs_mounted) {
        pthread_mutex_unlock(&pfs_mount_lock);
        return 0;
    }
    ret = pfsd_mount(o->cluster, o->pbd, o->hostid, PFS_RDWR); 
    if (ret) {
        pthread_mutex_unlock(&pfs_mount_lock);
        return 1;
    }
    pfs_data.pfs_mounted = 1;
    strcpy(pfs_data.pbd, o->pbd);
    td->o.use_thread = 1;
    pthread_mutex_unlock(&pfs_mount_lock);
    return 0;
}

static void fio_pfs_disconnect(void)
{
    pthread_mutex_lock(&pfs_mount_lock);
    if (pfs_data.pfs_mounted)
        pfsd_umount(pfs_data.pbd); 
    pfs_data.pfs_mounted = false;
    pthread_mutex_unlock(&pfs_mount_lock);
}

static int fio_io_end(struct thread_data *td, struct io_u *io_u, int ret)
{
    if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
        LAST_POS(io_u->file) = io_u->offset + ret;

    if (ret != (int) io_u->xfer_buflen) {
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
        ret = pfsd_pread(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
    else if (io_u->ddir == DDIR_WRITE)
        ret = pfsd_pwrite(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
    else {
        log_err("pfs: trim is not supported");
        return FIO_Q_COMPLETED;
    }

    return fio_io_end(td, io_u, ret);
}

static int fio_pfs_init(struct thread_data *td)
{
    return fio_pfs_connect(td);
}

static void fio_pfs_cleanup(struct thread_data *td)
{
}

static int fio_pfs_open_file(struct thread_data *td, struct fio_file *f)
{
    int flags = 0;

    dprint(FD_FILE, "fd open %s\n", f->file_name);

    if (td->o.create_on_open && td->o.allow_create)
        flags |= O_CREAT;

    if (td_trim(td)) {
        td_verror(td, EINVAL, "pfs does not support trim");
        return 1;
    }

    if (td_write(td)) {
        if (!read_only)
            flags |= O_RDWR;

        if (f->filetype == FIO_TYPE_FILE && td->o.allow_create)
            flags |= O_CREAT;
    } else if (td_read(td)) {
        flags |= O_RDONLY;
    }

    f->fd = pfsd_open(f->file_name, flags, 0600);
    if (f->fd == -1) {
        char buf[FIO_VERROR_SIZE];
        int __e = errno;

        snprintf(buf, sizeof(buf), "open(%s)", f->file_name);
        td_verror(td, __e, buf);
        return 1;
    }

    return 0;
}

static int fio_pfs_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
    int ret = 0;

    dprint(FD_FILE, "fd close %s\n", f->file_name);

    if (pfsd_close(f->fd) < 0)
        ret = errno;

    f->fd = -1;

    f->engine_pos = 0;
    return ret;
}

static int fio_pfs_file_size(struct thread_data *td, struct fio_file *f)
{
    struct stat st;

    if (fio_pfs_connect(td))
        return 1;

    if (pfsd_stat(f->file_name, &st) == -1) {
        td_verror(td, errno, "fstat");
        return 1;
    }

    f->real_file_size = st.st_size;
    return 0;
}

static struct ioengine_ops ioengine_prw = {
    .name       = "pfs",
    .version    = FIO_IOOPS_VERSION,
    .init       = fio_pfs_init,
    .cleanup    = fio_pfs_cleanup,
    .queue      = fio_pfs_queue,
    .open_file  = fio_pfs_open_file,
    .close_file = fio_pfs_close_file,
    .get_file_size  = fio_pfs_file_size,
    .flags      = FIO_DISKLESSIO | FIO_SYNCIO,
    .options    = options,
    .option_struct_size = sizeof(struct pfs_options),
};

static void fio_init fio_pfs_register(void)
{
    register_ioengine(&ioengine_prw);
}

static void fio_exit fio_pfs_unregister(void)
{
    fio_pfs_disconnect();
    unregister_ioengine(&ioengine_prw);
}
