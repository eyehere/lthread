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
 * lthread_socket.c
 */


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>

#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "lthread_int.h"

#if defined(__FreeBSD__) || defined(__APPLE__)
    #define FLAG
#else
    #define FLAG | MSG_NOSIGNAL
#endif

/* FIXME check for EWOULDBLOCK along with EAGAIN? */

#ifdef LTHREAD_SOCKET_PASSTHROUGH
/* let symbol-modified librarys work outside the lthread */
#define LTHREAD_SOCKET_CHECK_SCHED(y)                       \
    if (1) {                                                \
        struct lthread_sched *sched = lthread_get_sched();  \
        if (!sched || !sched->current_lthread)              \
            return (y);                                     \
    }
#else
#define LTHREAD_SOCKET_CHECK_SCHED(y)
#endif

/* obtain timeout from fd, if zero is given; critical for usage with openssl */
#ifdef LTHREAD_TIMEOUT_FROM_SOCKET
static inline uint64_t
socket_get_timeout(int fd, int timeo_name, uint64_t timeo) {
    if (timeo)
        return timeo;

    struct timeval tv;
    socklen_t optlen = sizeof(tv);
    if (getsockopt(fd, SOL_SOCKET, timeo_name, &tv, &optlen) == 0) {
        return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
    } else {
        if (errno != ENOTSOCK)
            perror("lthread getsockopt");
        return 0;
    }
}

#define LTHREAD_GET_SOCKET_TIMEOUT(fd, opt, t) \
    socket_get_timeout(fd, opt, t)

#else
#define LTHREAD_GET_SOCKET_TIMEOUT(fd, opt, t) t
#endif


#define LTHREAD_RECV(x, y, t)                               \
x {                                                         \
    LTHREAD_SOCKET_CHECK_SCHED(y);                          \
    ssize_t ret = 0;                                        \
    struct lthread *lt = lthread_get_sched()->current_lthread;   \
    while (1) {                                             \
        if (lt->state & BIT(LT_ST_FDEOF))                   \
            return (0);                                     \
        _lthread_renice(lt);                                \
        ret = y;                                            \
        if (ret == -1 && errno != EAGAIN)                   \
            return (-1);                                    \
        if ((ret == -1 && errno == EAGAIN)) {               \
            _lthread_sched_event(lt, fd, LT_EV_READ,        \
            LTHREAD_GET_SOCKET_TIMEOUT(fd, SO_RCVTIMEO, t));   \
            if (lt->state & BIT(LT_ST_EXPIRED)) {           \
                return (-2);                                \
            }                                               \
        }                                                   \
        if (ret >= 0)                                       \
            return (ret);                                   \
    }                                                       \
}                                                           \

#define LTHREAD_RECV_EXACT(x, y)                            \
x {                                                         \
    ssize_t ret = 0;                                        \
    ssize_t recvd = 0;                                      \
    struct lthread *lt = lthread_get_sched()->current_lthread;   \
                                                            \
    while (recvd != length) {                               \
        if (lt->state & BIT(LT_ST_FDEOF))                   \
            return (0);                                     \
                                                            \
        _lthread_renice(lt);                                \
        ret = y;                                            \
        if (ret == 0)                                       \
            return (recvd);                                 \
        if (ret > 0)                                        \
            recvd += ret;                                   \
        if (ret == -1 && errno != EAGAIN)                   \
            return (-1);                                    \
        if ((ret == -1 && errno == EAGAIN)) {               \
            _lthread_sched_event(lt, fd, LT_EV_READ, timeout);   \
            if (lt->state & BIT(LT_ST_EXPIRED))             \
                return (-2);                                \
        }                                                   \
    }                                                       \
    return (recvd);                                         \
}                                                           \

#define LTHREAD_SEND(x, y)                                  \
x {                                                         \
    ssize_t ret = 0;                                        \
    ssize_t sent = 0;                                       \
    LTHREAD_SOCKET_CHECK_SCHED(y);                          \
    struct lthread *lt = lthread_get_sched()->current_lthread;   \
    while (sent != length) {                                \
        if (lt->state & BIT(LT_ST_FDEOF)) {                 \
            errno = EPIPE;                                  \
            return (-1);                                    \
        }                                                   \
        _lthread_renice(lt);                                \
        ret = y;                                            \
        if (ret == 0)                                       \
            return (sent);                                  \
        if (ret > 0)                                        \
            sent += ret;                                    \
        if (ret == -1 && errno != EAGAIN)                   \
            return (-1);                                    \
        if (ret == -1 && errno == EAGAIN)                   \
            _lthread_sched_event(lt, fd, LT_EV_WRITE, 0);   \
    }                                                       \
    return (sent);                                          \
}                                                           \

#define LTHREAD_SEND_ONCE(x, y)                             \
x {                                                         \
    ssize_t ret = 0;                                        \
    struct lthread *lt = lthread_get_sched()->current_lthread;   \
    while (1) {                                             \
        if (lt->state & BIT(LT_ST_FDEOF)) {                 \
            errno = EPIPE;                                  \
            return (-1);                                    \
        }                                                   \
        ret = y;                                            \
        if (ret >= 0)                                       \
            return (ret);                                   \
        if (ret == -1 && errno != EAGAIN)                   \
            return (-1);                                    \
        if (ret == -1 && errno == EAGAIN)                   \
            _lthread_sched_event(lt, fd, LT_EV_WRITE, 0);   \
    }                                                       \
}                                                           \

const struct linger nolinger = { .l_onoff = 1, .l_linger = 1 };

int
lthread_accept(int fd, struct sockaddr *addr, socklen_t *len)
{
    LTHREAD_SOCKET_CHECK_SCHED(accept(fd, addr, len));
    int ret = -1;
    struct lthread *lt = lthread_get_sched()->current_lthread;

    while (1) {
        _lthread_renice(lt);
        ret = accept(fd, addr, len);
        if (ret == -1 && 
            (errno == ENFILE || 
            errno == EWOULDBLOCK ||
            errno == EMFILE)) {
            _lthread_sched_event(lt, fd, LT_EV_READ, 0);
            continue;
        }

        if (ret > 0)
            break;

        if (ret == -1 && errno == ECONNABORTED)  {
            perror("Cannot accept connection");
            continue;
        }

        if (ret == -1 && errno != EWOULDBLOCK) {
            fprintf(stderr, "Cannot accept connection on %d: %s\n", fd, strerror(errno));
            return (-1);
        }

    }

#ifndef __FreeBSD__
    if ((fcntl(ret, F_SETFL, O_NONBLOCK)) == -1) {
        close(fd);
        perror("Failed to set socket properties");
        return (-1);
    }
#endif

    return (ret);
}

int
lthread_close(int fd)
{
    LTHREAD_SOCKET_CHECK_SCHED(close(fd));
    struct lthread *lt = NULL;

    /* wake up the lthreads waiting on this fd and notify them of close */
    lt = _lthread_desched_event(fd, LT_EV_READ);
    if (lt) {
        TAILQ_INSERT_TAIL(&lthread_get_sched()->ready, lt, ready_next);
        lt->state |= BIT(LT_ST_FDEOF);
    }

    lt = _lthread_desched_event(fd, LT_EV_WRITE);
    if (lt) {
        TAILQ_INSERT_TAIL(&lthread_get_sched()->ready, lt, ready_next);
        lt->state |= BIT(LT_ST_FDEOF);
    }

    /* closing fd removes its registered events from poller */ 
    return (close(fd));
}

int
lthread_socket(int domain, int type, int protocol)
{
    int fd;
#if defined(__FreeBSD__) || defined(__APPLE__)
    int set = 1;
#endif

    if ((fd = socket(domain, type, protocol)) == -1) {
        perror("Failed to create a new socket");
        return (-1);
    }

    LTHREAD_SOCKET_CHECK_SCHED(fd);

    if ((fcntl(fd, F_SETFL, O_NONBLOCK)) == -1) {
        close(fd);
        perror("Failed to set socket properties");
        return (-1);
    }

#if defined(__FreeBSD__) || defined(__APPLE__)
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(int)) == -1) {
        close(fd);
        perror("Failed to set socket properties");
        return (-1);
    }
#endif

    return (fd);
}

/* forward declare lthread_recv for use in readline */
ssize_t lthread_recv(int fd, void *buf, size_t buf_len, int flags,
    uint64_t timeout);

ssize_t
lthread_readline(int fd, char **buf, size_t max, uint64_t timeout)
{
    size_t cur = 0;
    ssize_t r = 0;
    size_t total_read = 0;
    char *data = NULL;

    data = calloc(1, max + 1);
    if (data == NULL)
        return (-1);

    while (total_read < max) {
        r = lthread_recv(fd, data + total_read, 1, 0, timeout);

        if (r == 0 || r == -2 || r == -1) {
            free(data);
            return (r);
        }

        total_read += 1;
        if (data[cur++] == '\n')
            break;
    }

    *buf = data;

    return (total_read);
}

int
lthread_pipe(int fildes[2])
{
    int ret = 0;

    ret = pipe(fildes);
    if (ret != 0)
        return (ret);

    LTHREAD_SOCKET_CHECK_SCHED(ret);

    ret = fcntl(fildes[0], F_SETFL, O_NONBLOCK);
    if (ret != 0)
        goto err;

    ret = fcntl(fildes[1], F_SETFL, O_NONBLOCK);
    if (ret != 0)
        goto err;

    return (0);

err:
    close(fildes[0]);
    close(fildes[1]);
    return (ret);
}

LTHREAD_RECV(
    ssize_t lthread_recv(int fd, void *buf, size_t length, int flags,
        uint64_t timeout),
    recv(fd, buf, length, flags FLAG),
    timeout
)

LTHREAD_RECV(
    ssize_t lthread_read(int fd, void *buf, size_t length,
        uint64_t timeout),
    read(fd, buf, length),
    timeout
)

LTHREAD_RECV(
    ssize_t lthread_read_posix(int fd, void *buf, size_t length),
    read(fd, buf, length),
    0
)

LTHREAD_RECV(
    ssize_t lthread_recv_posix(int fd, void *buf, size_t length, int flags),
    recv(fd, buf, length, flags FLAG),
    0
)

LTHREAD_RECV(
    ssize_t lthread_recvmsg_posix(int fd, struct msghdr *message, int flags),
    recvmsg(fd, message, flags FLAG),
    0
)

LTHREAD_RECV(
    ssize_t lthread_recvfrom_posix(int fd, void *buf, size_t length, int flags,
        struct sockaddr *address, socklen_t *address_len),
    recvfrom(fd, buf, length, flags FLAG, address, address_len),
    0
)

LTHREAD_RECV_EXACT(
    ssize_t lthread_recv_exact(int fd, void *buf, size_t length, int flags,
        uint64_t timeout),
    recv(fd, buf + recvd, length - recvd, flags FLAG)
)

LTHREAD_RECV_EXACT(
    ssize_t lthread_read_exact(int fd, void *buf, size_t length,
        uint64_t timeout),
    read(fd, buf + recvd, length - recvd)
)

LTHREAD_RECV(
    ssize_t lthread_recvmsg(int fd, struct msghdr *message, int flags,
        uint64_t timeout),
    recvmsg(fd, message, flags FLAG),
    timeout
)

LTHREAD_RECV(
    ssize_t lthread_recvfrom(int fd, void *buf, size_t length, int flags,
        struct sockaddr *address, socklen_t *address_len, uint64_t timeout),
    recvfrom(fd, buf, length, flags FLAG, address, address_len),
    timeout
)

LTHREAD_SEND(
    ssize_t lthread_send(int fd, const void *buf, size_t length, int flags),
    send(fd, ((char *)buf) + sent, length - sent, flags FLAG)
)

LTHREAD_SEND(
    ssize_t lthread_write(int fd, const void *buf, size_t length),
    write(fd, ((char *)buf) + sent, length - sent)
)

LTHREAD_SEND_ONCE(
    ssize_t lthread_sendmsg(int fd, const struct msghdr *message, int flags),
    sendmsg(fd, message, flags FLAG)
)

LTHREAD_SEND_ONCE(
    ssize_t lthread_sendto(int fd, const void *buf, size_t length, int flags,
        const struct sockaddr *dest_addr, socklen_t dest_len),
    sendto(fd, buf, length, flags FLAG, dest_addr, dest_len)
)


/*
ssize_t lthread_write(int fd, const void *buf, size_t length)
{                                                       
    ssize_t ret = 0;                                      
    ssize_t sent = 0;                                     
    LTHREAD_SOCKET_CHECK_SCHED(write(fd, ((char *)buf) + sent, length - sent));
    struct lthread *lt = lthread_get_sched()->current_lthread;
    while (sent != length) {                              
        if (lt->state & BIT(LT_ST_FDEOF)) {
            errno = EPIPE;
            return (-1);
        }
        _lthread_renice(lt);                              
        ret = write(fd, ((char *)buf) + sent, length - sent);
        if (ret == 0)                                     
            return (sent);                                
        if (ret > 0)                                      
            sent += ret;                                  
        if (ret == -1 && errno != EAGAIN)                 
            return (-1);                                  
        if (ret == -1 && errno == EAGAIN)                 
            _lthread_sched_event(lt, fd, LT_EV_WRITE, 0); 
    }                                                     
    return (sent);                                        
}                                                         
*/



static inline int
_lthread_connect(int fd, struct sockaddr *name, socklen_t namelen,
    uint64_t timeout)
{
    LTHREAD_SOCKET_CHECK_SCHED(connect(fd, name, namelen));
    int ret = 0;
    struct lthread *lt = lthread_get_sched()->current_lthread;

    while (1) {
        _lthread_renice(lt);
        ret = connect(fd, name, namelen);
        if (ret == 0)
            break;
        if (ret == -1 && (errno == EAGAIN || 
            errno == EWOULDBLOCK ||
            errno == EINPROGRESS)) {
            _lthread_sched_event(lt, fd, LT_EV_WRITE, timeout);
            if (lt->state & BIT(LT_ST_EXPIRED))
                return (-2);

            ret = 0;
            break;
        } else {
            break;
        }
    }

    return (ret);
}

int
lthread_connect(int fd, struct sockaddr *name, socklen_t namelen,
    uint64_t timeout)
{
    return _lthread_connect(fd, name, namelen, timeout);
}

int
lthread_connect_posix(int fd, struct sockaddr *name, socklen_t namelen)
{
    return _lthread_connect(fd, name, namelen, 0);
}

ssize_t
lthread_writev(int fd, struct iovec *iov, int iovcnt)
{
    LTHREAD_SOCKET_CHECK_SCHED(writev(fd, iov, iovcnt));
    ssize_t total = 0;
    int iov_index = 0;
    struct lthread *lt = lthread_get_sched()->current_lthread;

    do {
        _lthread_renice(lt);
        ssize_t n = writev(fd, iov + iov_index, iovcnt - iov_index);
        if (n > 0) {
            int i = 0;
            total += n;
            for (i = iov_index; i < iovcnt && n > 0; i++) {
                if (n < iov[i].iov_len) {
                    iov[i].iov_base += n;
                    iov[i].iov_len -= n;
                    n = 0;
                } else {
                    n -= iov[i].iov_len;
                    iov_index++;
                }
            }
        } else if (-1 == n && EAGAIN == errno) {
            _lthread_sched_event(lt, fd, LT_EV_WRITE, 0);
        } else {
            return (n);
        }
    } while (iov_index < iovcnt);

    return (total);
}

#ifdef __FreeBSD__
int
lthread_sendfile(int fd, int s, off_t offset, size_t nbytes,
    struct sf_hdtr *hdtr)
{

    off_t sbytes = 0;
    int ret = 0;
    struct lthread *lt = lthread_get_sched()->current_lthread;

    do {
        ret = sendfile(fd, s, offset, nbytes, hdtr, &sbytes, 0);

        if (ret == 0)
            return (0);

        if (sbytes)
            offset += sbytes;

        sbytes = 0;

        if (ret == -1 && EAGAIN == errno)
            _lthread_sched_event(lt, s, LT_EV_WRITE, 0);
        else if (ret == -1)
            return (-1);

    } while (1);
}
#endif

int lthread_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (timeout == 0)
        return poll(fds, nfds, 0);

    LTHREAD_SOCKET_CHECK_SCHED(poll(fds, nfds, timeout));
    struct lthread *lt = lthread_get_sched()->current_lthread;
    _lthread_renice(lt); /* doubt if it's necessary */

    return _lthread_sched_events_poll(lt, fds, nfds, timeout);
}
