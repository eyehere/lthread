/*
 * Written by wisd0me, to illustrate and test lthread_poll();
 * server accepts clients, and exchanges HELLO & END messages with them
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "lthread.h"

#define MAX_CLIENTS 32 /* if this amount of clients will be served, the test considered as completed */

struct conn {
    int fd;
};

enum PROTO_MSGS { PROTO_HELLO, PROTO_END, PROTO_INVAL };

int
_proto_read(int fd, void *buf, size_t size, const char *ident) {
    int ret = lthread_read_posix(fd, buf, size);
    /* int ret = lthread_recv(fd, buf, size, 0, 1000); */
    if (ret == -1)
        fprintf(stderr, "%s: error reading: %s\n", ident, strerror(errno));
    return ret;
}

int
_proto_write(int fd, void *buf, size_t size, const char *ident) {
    int ret = lthread_write(fd, buf, size);
    /* int ret = lthread_send(fd, buf, size, 0); */
    if (ret == -1)
        fprintf(stderr, "%s: error writing: %s\n", ident, strerror(errno));
    return ret;
}

#define proto_read(fd, buf, siz) _proto_read(fd, buf, siz, __FUNCTION__)
#define proto_write(fd, buf, siz) _proto_write(fd, buf, siz, __FUNCTION__)

void
client_log(size_t id, const char *fmt, ...) {
    va_list ap;
    char buf[BUFSIZ];

    snprintf(buf, sizeof(buf), "client %zd: %s", id, fmt);
    va_start(ap, fmt);
    vprintf(buf, ap);
    va_end(ap);
}

void
client(void *arg)
{
    int s, len;
    size_t id = *(size_t *) arg;
    struct sockaddr_un remote;

    client_log(id, "run\n");
    lthread_detach();
    lthread_sleep(200);

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, "/tmp/lthread.sock");
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if ((s = lthread_socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    client_log(id, "connecting\n");
    if (lthread_connect(s, (struct sockaddr *)&remote, len, 0) == -1) {
        perror("connect");
        exit(1);
    }

    int msg = PROTO_HELLO;
    int ret;

    ret = proto_write(s, &msg, sizeof(msg));
    assert(ret > 0);

    msg = PROTO_INVAL;
    ret = proto_read(s, &msg, sizeof(msg));
    assert(msg == PROTO_HELLO);
    if (ret > 0) printf("%s: read server HELLO, %d bytes, %d\n", __FUNCTION__, ret, msg);

    msg = PROTO_END;
    ret = proto_write(s, &msg, sizeof(msg));
    assert(ret > 0);
    client_log(id, "sent END to server\n");

    msg = PROTO_INVAL;
    ret = proto_read(s, &msg, sizeof(msg));
    assert(msg == PROTO_END);
    if (ret > 0) client_log(id, "read server END, %d bytes, %d\n", ret, msg);

    client_log(id, "[+] done\n");
    lthread_close(s);
    return;
}

void
socket_server_process_client(void *cli_fd)
{
    int fd = ((struct conn *)cli_fd)->fd;
    int r, end = 0, msg = PROTO_INVAL;

    lthread_detach();
    printf("%s: run\n", __FUNCTION__);

    while ( (r = proto_read(fd, &msg, sizeof(msg))) > 0) {
        switch (msg) {
        case PROTO_HELLO:
            printf("%s: read client HELLO, %d bytes, code %d\n", __FUNCTION__, r, msg);
            if (proto_write(fd, &msg, sizeof(msg)) > 0)
                printf("%s: sent response HELLO\n", __FUNCTION__);
            break;
        case PROTO_END:
            msg = PROTO_END;
            printf("%s: read client END, %d bytes, code %d\n", __FUNCTION__, r, msg);
            if (proto_write(fd, &msg, sizeof(msg)) > 0)
                printf("%s: sent END message\n", __FUNCTION__);
            end = 1;
            break;
        default:
            printf("%s: invalid message %d\n", __FUNCTION__, msg);
            assert(0);
            break;
        }
        msg = PROTO_INVAL;
    }

    assert(end);
    lthread_close(fd);
    free(cli_fd);
}

void
server(void *arg)
{
    int fd = 0;
    int cli_fd = 0;
    socklen_t len = 0;
    lthread_t *lt;
    struct sockaddr_un local, remote;

    lthread_detach();
    fd = lthread_socket(AF_UNIX, SOCK_STREAM, 0);

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, "/tmp/lthread.sock");
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);

    bind(fd, (struct sockaddr *)&local, len);
    listen(fd, 100);

    struct pollfd fds = { .fd = fd, .events = POLLIN };
    int ret;
    size_t clients_count = 0;

    fprintf(stdout, "running poll on inactive socket without timeout, time %lu\n", time(NULL));
    ret = lthread_poll(&fds, 1, 0);
    fprintf(stdout, "poll returned %d, events %d, time %lu\n", ret, fds.revents, time(NULL));
    assert(ret == 0);
    puts("[+] noevent poll tested\n");

    while (clients_count < MAX_CLIENTS) {
        fprintf(stdout, "%s: waiting for events\n", __FUNCTION__);
        ret = lthread_poll(&fds, 1, -1);
        fprintf(stdout, "%s: poll returned %d, events %d\n", __FUNCTION__, ret, fds.revents);
        if (ret == -1)
            return;

        if (!(fds.revents & POLLHUP) && fds.revents & POLLIN) {
            fprintf(stdout, "%s: got input event on polled fd\n", __FUNCTION__);
            len = sizeof(struct sockaddr_un);
            cli_fd = lthread_accept(fd, (struct sockaddr *)&remote, &len);
            assert(cli_fd != -1);
            printf("%s: listenfd %d, client %d\n", __FUNCTION__, fd, cli_fd);
            struct conn *c = calloc(1, sizeof(struct conn));
            if (c) {
                c->fd = cli_fd;
                lthread_create(&lt, socket_server_process_client, c);
                clients_count++;
            }
        } else {
            fprintf(stdout, "%s: POLLHUP\n", __FUNCTION__);
        }
    }
    printf("[+] %s: clients count reached maximum, exiting\n", __FUNCTION__);
    return;
}

int
main(int argc, char **argv)
{
    lthread_t *srv = NULL;
    lthread_t *lt = NULL;

    lthread_create(&srv, server, NULL);

    size_t count = 0, ids[MAX_CLIENTS];
    while (count < MAX_CLIENTS) {
        ids[count] = count;
        lthread_create(&lt, client, &ids[count]);
        count++;
    }

    lthread_run();
    return 0;
}
