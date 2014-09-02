/*
 * Lthread
 * Copyright (C) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * lthread_sched.c
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <inttypes.h>

#include "lthread_int.h"
#include "tree.h"

#define FD_KEY(f,e) (((int64_t)(f) << (sizeof(int32_t) * 8)) | e)
#define FD_EVENT(f) ((int32_t)(f))
#define FD_ONLY(f) ((f) >> ((sizeof(int32_t) * 8)))

static inline int _lthread_sleep_cmp(struct lthread *l1, struct lthread *l2);
static inline int _lthread_wait_cmp(struct lthread *l1, struct lthread *l2);

static inline int
_lthread_sleep_cmp(struct lthread *l1, struct lthread *l2)
{
    if (l1->sleep_usecs < l2->sleep_usecs)
        return (-1);
    if (l1->sleep_usecs == l2->sleep_usecs)
        return (0);
    return (1);
}

static inline int
_lthread_wait_cmp(struct lthread *l1, struct lthread *l2)
{
    if (l1->fd_wait < l2->fd_wait)
        return (-1);
    if (l1->fd_wait == l2->fd_wait)
        return (0);
    return (1);
}

RB_GENERATE(lthread_rb_sleep, lthread, sleep_node, _lthread_sleep_cmp);
RB_GENERATE(lthread_rb_wait, lthread, wait_node, _lthread_wait_cmp);

static uint64_t _lthread_min_timeout(struct lthread_sched *);

static int  _lthread_poll(void);
static void _lthread_resume_expired(struct lthread_sched *sched);
static inline int _lthread_sched_isdone(struct lthread_sched *sched);

static int
_lthread_poll(void)
{
    struct lthread_sched *sched;
    sched = lthread_get_sched();
    struct timespec t = {0, 0};
    int ret = 0;
    uint64_t usecs = 0;

    sched->num_new_events = 0;
    usecs = _lthread_min_timeout(sched);

    /* never sleep if we have an lthread pending in the new queue */
    if (usecs && TAILQ_EMPTY(&sched->ready)) {
        t.tv_sec =  usecs / 1000000u;
        if (t.tv_sec != 0)
            t.tv_nsec  =  (usecs % 1000u)  * 1000000u;
        else
            t.tv_nsec = usecs * 1000u;
    } else {
        t.tv_nsec = 0;
        t.tv_sec = 0;
    }

    int i;
    for (i = 0; i < 1024; i++) {
        ret = _lthread_poller_poll(t);

        if (ret == -1) {
            int errcode = errno;
            if (errcode == EINTR)
                continue;
            else
                assert(0);
        }

        break;
    }

    sched->nevents = 0;
    sched->num_new_events = ret == -1 ? 0 : ret;

    return (0);
}

static uint64_t
_lthread_min_timeout(struct lthread_sched *sched)
{
    uint64_t t_diff_usecs = 0, min = 0;
    struct lthread *lt = NULL;

    t_diff_usecs = _lthread_diff_usecs(sched->birth,
        _lthread_usec_now());
    min = sched->default_timeout;

    lt = RB_MIN(lthread_rb_sleep, &sched->sleeping);
    if (!lt)
        return (min);

    min = lt->sleep_usecs;
    if (min > t_diff_usecs)
        return (min - t_diff_usecs);
    else // we are running late on a thread, execute immediately
        return (0);

    return (0);
}

/*
 * Returns 0 if there is a pending job in scheduler or 1 if done and can exit.
 */
static inline int
_lthread_sched_isdone(struct lthread_sched *sched)
{
    return (RB_EMPTY(&sched->waiting) &&
        LIST_EMPTY(&sched->busy) &&
        RB_EMPTY(&sched->sleeping) &&
        TAILQ_EMPTY(&sched->ready) &&
        cfuhash_num_entries(sched->waiting_multi) == 0);
}

void
lthread_run(void)
{
    struct lthread_sched *sched;
    struct lthread *lt = NULL, *lt_tmp = NULL;
    struct lthread *lt_read = NULL, *lt_write = NULL;
    int p = 0;
    int fd = 0;
    int is_eof = 0;

    sched = lthread_get_sched();
    /* scheduler not initiliazed, and no lthreads where created */
    if (sched == NULL)
        return;

    while (!_lthread_sched_isdone(sched)) {

        /* 1. start by checking if a sleeping thread needs to wakeup */
        _lthread_resume_expired(sched);

        /* 2. check to see if we have any ready threads to run */
        while (!TAILQ_EMPTY(&sched->ready)) {
            TAILQ_FOREACH_SAFE(lt, &sched->ready, ready_next, lt_tmp) {
                TAILQ_REMOVE(&lt->sched->ready, lt, ready_next);
                _lthread_resume(lt);
            }
        }

        /* 3. resume lthreads we received from lthread_compute, if any */
        while (1) {
            assert(pthread_mutex_lock(&sched->defer_mutex) == 0);
            lt = TAILQ_FIRST(&sched->defer);
            if (lt == NULL) {
                assert(pthread_mutex_unlock(&sched->defer_mutex) == 0);
                break;
            }
            TAILQ_REMOVE(&sched->defer, lt, defer_next);
            assert(pthread_mutex_unlock(&sched->defer_mutex) == 0);
            LIST_REMOVE(lt, busy_next);
            _lthread_resume(lt);
        }

        /* 4. check if we received any events after lthread_poll */
        _lthread_poll();

        /* 5. fire up lthreads that are ready to run */
        while (sched->num_new_events) {
            p = --sched->num_new_events;

            fd = _lthread_poller_ev_get_fd(&sched->eventlist[p]);
            if (INVALID_SOCKET(fd)) /* skip sockets that was already processed by _lthread_desched_events() */
                continue;

            /* 
             * We got signaled via trigger to wakeup from polling & resume file io.
             * Those lthreads will get handled in step 4.
             */
            if (fd == sched->eventfd) {
                _lthread_poller_ev_clear_trigger();
                continue;
            }

            is_eof = _lthread_poller_ev_is_eof(&sched->eventlist[p]);
            if (is_eof)
                errno = ECONNRESET;

            /*
             * per-lthread multiple events handling: all fds belonging to signle lthread
             * will be handled at 1 invocation of _lthread_desched_events()
             */
            lt = _lthread_desched_events(fd, 0);
            if (lt) {
                TAILQ_INSERT_TAIL(&lt->sched->ready, lt, ready_next);
                /* _lthread_resume(lt); */
                continue;
            }

            lt_read = _lthread_desched_event(fd, LT_EV_READ);
            if (lt_read != NULL) {
                if (is_eof)
                    lt_read->state |= BIT(LT_ST_FDEOF);
                _lthread_resume(lt_read);
            }

            lt_write = _lthread_desched_event(fd, LT_EV_WRITE);
            if (lt_write != NULL) {
                if (is_eof)
                    lt_write->state |= BIT(LT_ST_FDEOF);
                _lthread_resume(lt_write);
            }
            is_eof = 0;

            /* this assert is not necessary when using multiple schedulers in multiple threads */
/*
            if (lt_write == NULL && lt_read == NULL)
                fprintf(stderr, "sched %p, fd %d, new events %d\n", sched, fd, sched->num_new_events);
            assert(lt_write != NULL || lt_read != NULL);
*/
        }
    }

    _sched_free(sched);

    return;
}

/*
 * Cancels registered event in poller and deschedules (fd, ev) -> lt from
 * rbtree. This is safe to be called even if the lthread wasn't waiting on an
 * event. Lthreads waiting on multiple fds is handled either.
 */
void
_lthread_cancel_event(struct lthread *lt)
{
    if (lt->state & BIT(LT_ST_WAIT_READ)) {
        _lthread_poller_ev_clear_rd(FD_ONLY(lt->fd_wait));
        lt->state &= CLEARBIT(LT_ST_WAIT_READ);
    } else if (lt->state & BIT(LT_ST_WAIT_WRITE)) {
        _lthread_poller_ev_clear_wr(FD_ONLY(lt->fd_wait));
        lt->state &= CLEARBIT(LT_ST_WAIT_WRITE);
    } else if (lt->state & BIT(LT_ST_WAIT_MULTIPLE)) {
        nfds_t i, nfds = lt->multiple_evs_count;
        struct pollfd *fds = lt->multiple_evs;

        for (i = 0; i < nfds; i++) {
            if (!INVALID_SOCKET(fds[i].fd)) {
                if (!_lthread_desched_events(fds[i].fd, 1))
                    assert(0);
                break;
            }
        }
    }

    if (lt->fd_wait >= 0)
        _lthread_desched_event(FD_ONLY(lt->fd_wait),
            FD_EVENT(lt->fd_wait));
    lt->fd_wait = -1;
}

/*
 * Deschedules an event by removing the (fd, ev) -> lt node from rbtree.
 * It also deschedules the lthread from sleeping in case it was in sleeping
 * tree.
 */
struct lthread *
_lthread_desched_event(int fd, enum lthread_event e)
{
    struct lthread *lt = NULL;
    struct lthread_sched *sched = lthread_get_sched();
    struct lthread find_lt;

    /* memset not needed? */
    /* memset(&find_lt, 0, sizeof(find_lt)); */
    find_lt.fd_wait = FD_KEY(fd, e);

    lt = RB_FIND(lthread_rb_wait, &sched->waiting, &find_lt);
    if (lt != NULL) {
        RB_REMOVE(lthread_rb_wait, &lt->sched->waiting, lt);
        _lthread_desched_sleep(lt);
    }

    return (lt);
}

/*
 * Schedules an lthread for a poller event.
 * Sets its state to LT_EV_(READ|WRITE) and inserts lthread in waiting rbtree.
 * When the event occurs, the state is cleared and node is removed by 
 * _lthread_desched_event() called from lthread_run().
 *
 * If event doesn't occur and lthread expired waiting, _lthread_cancel_event()
 * must be called.
 */
void
_lthread_sched_event(struct lthread *lt, int fd, enum lthread_event e,
    uint64_t timeout)
{
    struct lthread *lt_tmp = NULL;
    enum lthread_st st;
    if (lt->state & BIT(LT_ST_WAIT_READ) || lt->state & BIT(LT_ST_WAIT_WRITE)) {
        printf("Unexpected event. lt id %"PRIu64" fd %"PRId64" already in %"PRId32" state\n",
            lt->id, lt->fd_wait, lt->state);
        assert(0);
    }

    if (e == LT_EV_READ) {
        st = LT_ST_WAIT_READ;
        _lthread_poller_ev_register_rd(fd);
    } else if (e == LT_EV_WRITE) {
        st = LT_ST_WAIT_WRITE;
        _lthread_poller_ev_register_wr(fd);
    } else
        assert(0);

    lt->state |= BIT(st);
    lt->fd_wait = FD_KEY(fd, e);
    lt_tmp = RB_INSERT(lthread_rb_wait, &lt->sched->waiting, lt);
    assert(lt_tmp == NULL);
    _lthread_sched_sleep(lt, timeout);
    lt->fd_wait = -1;
    lt->state &= CLEARBIT(st);
}

#ifdef LTHREAD_DEBUG
struct lthread *lthread_current();

int fe_fn(void *key, size_t key_size, void *data, size_t data_size, void *arg) {
    if (data == arg) {
        fprintf(stdout, "(%X) found not deleted lthread entry %lld %p in hash table!\n", (unsigned int) pthread_self(), *((int64_t *) key), data);
/*
        struct lthread_sched *sched = lthread_get_sched();
        FILE *fp = fopen("/tmp/ht.fault", "w");
        cfuhash_pretty_print(sched->waiting_multi, fp);
        fflush(fp);
        fclose(fp);
*/
        assert(0);
    }
    return 0;
}

void _lthread_check_ht(void) {
    struct lthread_sched *sched = lthread_get_sched();
    struct lthread *tgt = lthread_current();
    cfuhash_foreach(sched->waiting_multi, fe_fn, tgt);
}
#endif

/*
 * Deschedules the events by removing the chain of (fd, ev) -> lt nodes from hash table.
 * hash table check by fd is done. If ltread is there, process all it's fds, and mark
 * them as invalid sockets in eventlist, so lthread_run()'ll just skip'em
 * lt_expired parameter means all polled fds is expired, and function only
 * does cleanup from poller in that case.
 */
struct lthread *
_lthread_desched_events(int fd, int lt_expired) {
    struct lthread_sched *sched = lthread_get_sched();
    struct lthread *tgt = NULL;
    int64_t key;

    /* determine hash table key from poller if it returned with results */
    if (!lt_expired) {
        if (_lthread_poller_ev_is_read(&sched->eventlist[sched->num_new_events]))
            key = FD_KEY(fd, LT_EV_READ);
        else if (_lthread_poller_ev_is_write(&sched->eventlist[sched->num_new_events]))
            key = FD_KEY(fd, LT_EV_WRITE);
        if (cfuhash_get_data(sched->waiting_multi, &key, sizeof(key), (void **) &tgt, NULL) == 0)
            return NULL;
    } else { /* other way, try both cases */
        key = FD_KEY(fd, LT_EV_READ);
        if (cfuhash_get_data(sched->waiting_multi, &key, sizeof(key), (void **) &tgt, NULL) == 0) {
            key = FD_KEY(fd, LT_EV_WRITE);
            if (cfuhash_get_data(sched->waiting_multi, &key, sizeof(key), (void **) &tgt, NULL) == 0)
                return NULL;
        }
    }

    struct pollfd *fds = tgt->multiple_evs;
    nfds_t i, nfds = tgt->multiple_evs_count;
    void (*poller_ev_clear)(int fd);
    enum lthread_event ev;

    for (i = 0; i < nfds; i++) {
        if (INVALID_SOCKET(fds[i].fd))
            continue;

        /* determine the event type from the user given array */
        if (fds[i].events & POLLIN) {
            ev = LT_EV_READ;
            poller_ev_clear = _lthread_poller_ev_clear_rd;
        } else if (fds[i].events & POLLOUT) {
            ev = LT_EV_WRITE;
            poller_ev_clear = _lthread_poller_ev_clear_wr;
        } else {
            assert(0);
        }
        key = FD_KEY(fds[i].fd, ev);

        /* delete hash table entries and fill in the user's struct pollfd */
        assert(cfuhash_delete_data(sched->waiting_multi, &key, sizeof(key)));
        poller_ev_clear(fds[i].fd);

        int evidx; /* now, fill in users structure if the call wasn't expired */

        for (evidx = sched->num_new_events; !lt_expired && evidx >= 0; evidx--) {
            if (!INVALID_SOCKET(fds[i].fd) && fds[i].fd == _lthread_poller_ev_get_fd(&sched->eventlist[evidx])) {
                _lthread_poller_ev_set_fd(&sched->eventlist[evidx], -1); /* mark each poll-related fd to be skipped in sched->eventlist */
                tgt->multiple_evs_ready++; /* optimistically increase events count :] */
                if (_lthread_poller_ev_is_eof(&sched->eventlist[evidx]))
                    fds[i].revents |= POLLHUP;
                if (_lthread_poller_ev_is_read(&sched->eventlist[evidx]))
                    fds[i].revents |= POLLIN;
                else if (_lthread_poller_ev_is_write(&sched->eventlist[evidx]))
                    fds[i].revents |= POLLOUT;
                else
                    tgt->multiple_evs_ready--;

                break;
            }
        }
    }

    _lthread_desched_sleep(tgt);
#ifdef LTHREAD_DEBUG
    _lthread_check_ht();
#endif

    return tgt;
}

/*
 * Tend to wait on lthread for a multiple fds, poll() style.
 * Returns amount of ready descriptors.
 */
int
_lthread_sched_events_poll(struct lthread *lt, struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct lthread_sched *sched = lthread_get_sched();

    lt->state |= BIT(LT_ST_WAIT_MULTIPLE);
    lt->fd_wait = -1;
    lt->multiple_evs = fds; /* remember struct pollfd to let in-scheduler pick of all related descriptors effectively */
    lt->multiple_evs_count = nfds;

    if (timeout < 0)
        timeout = 0;

    nfds_t i;

    assert(fds != NULL);
    for (i = 0; i < nfds; i++) {
        if (INVALID_SOCKET(fds[i].fd))
            continue;

        enum lthread_event ev;

        if (fds[i].events & POLLIN) {
            ev = LT_EV_READ;
            _lthread_poller_ev_register_rd(fds[i].fd);
        } else if (fds[i].events & POLLOUT) {
            ev = LT_EV_WRITE;
            _lthread_poller_ev_register_wr(fds[i].fd);
        } else {
            assert(0);
        }

        /* add to sched->waiting_multi; fd & ev is the key, lthread pointer is the data */
        int64_t key = FD_KEY(fds[i].fd, ev);
        cfuhash_put_data(sched->waiting_multi, &key, sizeof(key), lt, sizeof(void *), NULL);
        fds[i].revents = 0;
    }

    _lthread_sched_sleep(lt, (uint64_t) timeout);
    int ret = lt->multiple_evs_ready;

    /*
     * Handle the case when lthread_poll() timed out. This way,
     * no _lthread_desched_events() will be called inside the scheduler.
     */
/* MOVED to _lthread_cancel_event()
    for (i = 0; i < nfds && lt->state & BIT(LT_ST_EXPIRED); i++) {
        if (!INVALID_SOCKET(fds[i].fd)) {
            if (!_lthread_desched_events(fds[i].fd, 1))
                assert(0);
            break;
        }
        }
*/

    lt->state &= CLEARBIT(LT_ST_WAIT_MULTIPLE);
    lt->multiple_evs = NULL;
    lt->multiple_evs_count = 0;
    lt->multiple_evs_ready = 0;

    return ret;
}

/*
 * Removes lthread from sleeping rbtree.
 * This can be called multiple times on the same lthread regardless if it was
 * sleeping or not.
 */
void
_lthread_desched_sleep(struct lthread *lt)
{
    if (lt->state & BIT(LT_ST_SLEEPING)) {
        RB_REMOVE(lthread_rb_sleep, &lt->sched->sleeping, lt);
        lt->state &= CLEARBIT(LT_ST_SLEEPING);
        lt->state |= BIT(LT_ST_READY);
        lt->state &= CLEARBIT(LT_ST_EXPIRED);
    }
}

/*
 * Schedules lthread to sleep for `msecs` by inserting lthread into sleeping
 * rbtree and setting the lthread state to LT_ST_SLEEPING.
 * lthread state is cleared upon resumption or expiry.
 */
void
_lthread_sched_sleep(struct lthread *lt, uint64_t msecs)
{
    struct lthread *lt_tmp = NULL;
    uint64_t usecs = msecs * 1000u;

    /*
     * if msecs is 0, we won't schedule lthread otherwise loop until
     * collision resolved(very rare) by incrementing sleep_usecs.
     */
    lt->sleep_usecs = _lthread_diff_usecs(lt->sched->birth,
        _lthread_usec_now()) + usecs;
    while (msecs) {
        lt_tmp = RB_INSERT(lthread_rb_sleep, &lt->sched->sleeping, lt);
        if (lt_tmp) {
            lt->sleep_usecs++;
            continue;
        }
        lt->state |= BIT(LT_ST_SLEEPING);
        break;
    }

    _lthread_yield(lt);
    if (msecs > 0)
        lt->state &= CLEARBIT(LT_ST_SLEEPING);
    lt->sleep_usecs = 0;
}

void
_lthread_sched_busy_sleep(struct lthread *lt, uint64_t msecs)
{

    LIST_INSERT_HEAD(&lt->sched->busy, lt, busy_next);
    lt->state |= BIT(LT_ST_BUSY);
    _lthread_sched_sleep(lt, msecs);
    lt->state &= CLEARBIT(LT_ST_BUSY);
    LIST_REMOVE(lt, busy_next);
}

/*
 * Resumes expired lthread and cancels its events whether it was waiting
 * on one or not, and deschedules it from sleeping rbtree in case it was
 * sleeping.
 */
static void
_lthread_resume_expired(struct lthread_sched *sched)
{
    struct lthread *lt = NULL;
    uint64_t t_diff_usecs = 0;

    /* current scheduler time */
    t_diff_usecs = _lthread_diff_usecs(sched->birth, _lthread_usec_now());

    while (1) {
        lt = RB_MIN(lthread_rb_sleep, &sched->sleeping);
        if (lt == NULL)
            break;

        if (lt->sleep_usecs <= t_diff_usecs) {
            _lthread_cancel_event(lt);
            _lthread_desched_sleep(lt);
            lt->state |= BIT(LT_ST_EXPIRED);

            /* don't clear expired if lthread exited/cancelled */
            if (_lthread_resume(lt) != -1)
                lt->state &= CLEARBIT(LT_ST_EXPIRED);

            continue;
        }
        break;
    }
}
