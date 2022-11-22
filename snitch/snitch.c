#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include "util.h"
#include "nl.h"
#include "nft.h"
#include "queue.h"
#include "map.h"
#include "array.h"

#define EPHEMERAL_PORT_START 1<<15

int foot_terminal = 0;
char home[1024] = {0};
char rules_file[1024] = {0};

typedef struct result_s {
	i32 id;
	i32 response;
} result_t;

typedef struct event_s {
	i32 id;
    i32 pid;
    char type;
    char namebuf[24];
    char exe[256];
    char cmdline[256];
    char databuf[256];
    char net_remote_domain[256];
} event_t;

pthread_mutex_t dns_lock;
MAP_INIT(dns, char*, 1<<16);

typedef struct rule_s {

    // shared fields
    char kind[8]; // send | recv
    char response[6];   // allow | deny
    char duration[16]; // 1-minute | 24-hour | forever
    char exe[256];
    char cmdline[256];

    // fields for: send | recv
    char port[256]; // %d | ephemeral
    char proto[16]; // udp | tcp | raw | socktype=%d

    // fields for: send
    char addr[256];

    // internal fields
    u8 meta; // mark existing rules for deletion check
    u32 creation; // epoch seconds

} rule_t;

pthread_mutex_t rules_file_lock;

pthread_mutex_t rules_lock;
i64 rules_file_mtime = 0;
i32 rules_file_needs_write = 0;
MAP_INIT(rules, rule_t*, 1<<16);

i32 rule_equal(rule_t *a, rule_t *b) {
    return \
        strncmp(a->kind,     b->kind,     sizeof(a->kind))     == 0 &&
        strncmp(a->response, b->response, sizeof(a->response)) == 0 &&
        strncmp(a->exe,      b->exe,      sizeof(a->exe))      == 0 &&
        strncmp(a->cmdline,  b->cmdline,  sizeof(a->cmdline))  == 0 &&
        strncmp(a->port,     b->port,     sizeof(a->port))     == 0 &&
        strncmp(a->proto,    b->proto,    sizeof(a->proto))    == 0 &&
        strncmp(a->addr,     b->addr,     sizeof(a->addr))     == 0;
}

rule_t *rule_parse(char *buf, i32 size) {
    i32 offset;
    rule_t *r;
    MALLOC(r, sizeof(*r));
    memset(r, 0, sizeof(*r));
    strcpy(r->duration, "forever");
    if (size < 6) {
        LOG("rule parse buf too small: %d\n", size);
        free(r);
        return NULL;
    }
    if (strncmp(buf, "send\t", 5) == 0) {
        // parse kind
        strcpy(r->kind, "send");
        buf += 5; size -= 5;
        // parse response
        if (size < 6) {
            LOG("rule parse buf too small\n");
            free(r);
            return NULL;
        }
        if (strncmp(buf, "allow\t", 6) == 0) {
            strcpy(r->response, "allow");
            buf += 6; size -= 6;
        } else if (strncmp(buf, "deny\t", 5) == 0) {
            strcpy(r->response, "deny");
            buf += 5; size -= 5;
        } else {
            LOG("rule parse bad response: %.*s\n", size, buf);
            free(r);
            return NULL;
        }
        // parse exe
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->exe, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse addr
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->addr, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse port
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->port, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse proto
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->proto, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse cmdline
        strncpy(r->cmdline, buf, size);
    } else if (strncmp(buf, "recv\t", 5) == 0) {
        // parse kind
        strcpy(r->kind, "recv");
        buf += 5; size -= 5;
        // parse response
        if (size < 6) {
            LOG("rule parse buf too small\n");
            free(r);
            return NULL;
        }
        if (strncmp(buf, "allow\t", 6) == 0) {
            strcpy(r->response, "allow");
            buf += 6; size -= 6;
        } else if (strncmp(buf, "deny\t", 5) == 0) {
            strcpy(r->response, "deny");
            buf += 5; size -= 5;
        } else {
            LOG("rule parse bad response: %.*s\n", size, buf);
            free(r);
            return NULL;
        }
        // parse exe
        offset = 0;
        for (i32 i = 0;; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->exe, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse port
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->port, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse proto
        offset = 0;
        for (i32 i = 0; i < size; i++) {
            offset = i;
            if (buf[i] == '\t')
                break;
        }
        if (offset >= size) {
            LOG("rule parse overflow\n");
            free(r);
            return NULL;
        }
        strncpy(r->proto, buf, offset);
        offset += 1; buf += offset; size -= offset;
        // parse cmdline
        strncpy(r->cmdline, buf, size);
    } else {
        LOG("rule parse unknown kind [%s]\n", r->kind);
        free(r);
        return NULL;
    }
    return r;
}

i32 rule_format(rule_t *r, char *buf, i32 size) {
    if (strcmp(r->kind, "send") == 0) {
        return snprintf(buf, size - 1, "%s\t%s\t%s\t%s\t%s\t%s\t%s", r->kind, r->response, r->exe, r->addr, r->port, r->proto, r->cmdline);
    } else if (strcmp(r->kind, "recv") == 0) {
        return snprintf(buf, size - 1, "%s\t%s\t%s\t%s\t%s\t%s", r->kind, r->response, r->exe, r->port, r->proto, r->cmdline);
    } else {
        ASSERT(0, "rule format unknown kind [%s]\n", r->kind);
    }
}

i32 rule_key(rule_t *r, char *buf, i32 size) {
    if (strcmp(r->kind, "send") == 0) {
        return snprintf(buf, size - 1, "send\t%s\t%s\t%s\t%s\t%s", r->exe, r->addr, r->port, r->proto, r->cmdline);
    } else if (strcmp(r->kind, "recv") == 0) {
        return snprintf(buf, size - 1, "recv\t%s\t%s\t%s\t%s", r->exe, r->port, r->proto, r->cmdline);
    } else {
        ASSERT(0, "unknown kind [%s]\n", r->kind);
    }
}

static int sortcmp(const void *p1, const void *p2) {
    return strcmp(*(const char**)p1, *(const char**)p2);
}

i32 add_rule(char *buf, i32 size) {
    rule_t *r;
    MALLOC(r, sizeof(*r));
    memset(r, 0, sizeof(*r));
    r->creation = unix_seconds();
    char keybuf[sizeof(*r)] = {0};
    i32 keysize;
    if (strcmp(buf, "send") == 0) {
        strncpy(r->kind,     buf, sizeof(r->kind) - 1);     buf += strlen(buf) + 1;
        strncpy(r->response, buf, sizeof(r->response) - 1); buf += strlen(buf) + 1;
        strncpy(r->duration, buf, sizeof(r->duration) - 1); buf += strlen(buf) + 1;
        strncpy(r->exe,      buf, sizeof(r->exe) - 1);      buf += strlen(buf) + 1;
        strncpy(r->addr,     buf, sizeof(r->addr) - 1);     buf += strlen(buf) + 1;
        strncpy(r->port,     buf, sizeof(r->port) - 1);     buf += strlen(buf) + 1;
        strncpy(r->proto,    buf, sizeof(r->proto) - 1);    buf += strlen(buf) + 1;
        strncpy(r->cmdline,  buf, sizeof(r->cmdline) - 1);  buf += strlen(buf) + 1;
        keysize = rule_key(r, keybuf, sizeof(keybuf));
    }
    else if (strcmp(buf, "recv") == 0) {
        strncpy(r->kind,     buf, sizeof(r->kind) - 1);     buf += strlen(buf) + 1;
        strncpy(r->response, buf, sizeof(r->response) - 1); buf += strlen(buf) + 1;
        strncpy(r->duration, buf, sizeof(r->duration) - 1); buf += strlen(buf) + 1;
        strncpy(r->exe,      buf, sizeof(r->exe) - 1);      buf += strlen(buf) + 1;
        strncpy(r->port,     buf, sizeof(r->port) - 1);     buf += strlen(buf) + 1;
        strncpy(r->proto,    buf, sizeof(r->proto) - 1);    buf += strlen(buf) + 1;
        strncpy(r->cmdline,  buf, sizeof(r->cmdline) - 1);  buf += strlen(buf) + 1;
        keysize = rule_key(r, keybuf, sizeof(keybuf));
    }
    else {
        LOG("error: unknown add-rule format: %s\n", buf);
        return DENY;
    }
    i32 response;
    if (strncmp(r->response, "allow", sizeof(r->response)) == 0) {
        response = ALLOW;
    } else if (strncmp(r->response, "deny", sizeof(r->response)) == 0) {
        response = DENY;
    } else {
        LOG("error: unknown response [%s]\n", r->response);
        return DENY;
    }

    if (strncmp(r->duration, "24-hour", sizeof(r->duration)) != 0 &&
        strncmp(r->duration, "forever", sizeof(r->duration)) != 0 &&
        strncmp(r->duration, "1-minute", sizeof(r->duration)) != 0)
    {
        LOG("error: unknown duration [%s]\n", r->duration);
        return DENY;
    }

    pthread_mutex_lock(&rules_lock); {
        MAP_FIND_INDEX(rules, keybuf, keysize);
        if (!MAP_KEY(rules)) {
            char *key;
            MALLOC(key, keysize + 1);
            memset(key, 0, keysize + 1);
            strncpy(key, keybuf, keysize);
            MAP_SET_INDEX(rules, (u8*)key, keysize, rule_t*);
        }
        if (MAP_VALUE(rules)) {
            free(MAP_VALUE(rules));
        }
        MAP_VALUE(rules) = r;
        if (strncmp(r->duration, "forever", sizeof(r->duration)) == 0) {
            rules_file_needs_write = 1;
        }
    }; pthread_mutex_unlock(&rules_lock);
    LOG("add-rule %s %s %s\n", r->response, r->duration, keybuf);

    return response;
}

char *sub_addr(char *addr, int size, int n) {
    int stop = 0;
    for (int i = 0; i < size; i++) {
        if (addr[i] == 0)
            break;
        stop++;
    }
    int count = -2;
    for (int i = stop - 1; i >= 0; i--) {
        if (addr[i] == '.')
            count ++;
        if (count > 2)
            break;
        if (count == n)
            return addr + i + 1;
    }
    return addr;
}

rule_t *match_rule(event_t *e) {
    rule_t r = {0};

    strncpy(r.exe, e->exe, sizeof(r.exe) - 1);
    strncpy(r.cmdline, e->cmdline, sizeof(r.cmdline) - 1);

    if (strcmp(e->namebuf, "socket_sendmsg") == 0) {
        snprintf(r.kind, sizeof(r.kind), "send");
        struct sockaddr_in *sin = (struct sockaddr_in*)e->databuf;
        if (e->net_remote_domain[0] != 0) {
            strncpy(r.addr, e->net_remote_domain, sizeof(r.addr));
        } else {
            ntoa(sin->sin_addr, r.addr, sizeof(r.addr));
        }
        if (e->type == SOCK_DGRAM) {
            strcpy(r.proto, "udp");
        } else if (e->type == SOCK_STREAM) {
            strcpy(r.proto, "tcp");
        } else if (e->type == SOCK_RAW) {
            strcpy(r.proto, "raw");
        } else {
            snprintf(r.proto, sizeof(r.proto) - 1, "socktype=%d", e->type);
        }
        snprintf(r.port, sizeof(r.port) - 1, "%d", ntohs(sin->sin_port));
    }

    else if (strcmp(e->namebuf, "socket_recvmsg") == 0) {
        snprintf(r.kind, sizeof(r.kind), "recv");
        struct sockaddr_in *sin = (struct sockaddr_in*)e->databuf;
        snprintf(r.port, sizeof(r.port) - 1, "%d", ntohs(sin->sin_port));
        if (e->type == SOCK_DGRAM) {
            strcpy(r.proto, "udp");
        } else if (e->type == SOCK_STREAM) {
            strcpy(r.proto, "tcp");
        } else if (e->type == SOCK_RAW) {
            strcpy(r.proto, "raw");
        } else {
            snprintf(r.proto, sizeof(r.proto) - 1, "socktype=%d", e->type);
        }
    }

    else {
        ASSERT(0, "unknown name [%s]\n", e->namebuf);
    }

    i32 nrs = 32;
    rule_t rs[nrs];
    memset(rs, 0, sizeof(rs));
    i32 i;

    if (strcmp(r.kind, "send") == 0) {
        if (strcmp(r.proto, "tcp") == 0 || strcmp(r.proto, "udp") == 0) {
            i = 0; rs[i] = r;
            i++;   rs[i] = r;                                                                sprintf(rs[i].addr, "*");
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*");
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*");                                   sprintf(rs[i].addr, "*");
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*"); sprintf(rs[i].port, "ephemeral"); sprintf(rs[i].addr, "*");
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*"); sprintf(rs[i].port, "ephemeral");
            i++;   rs[i] = r;                              sprintf(rs[i].port, "ephemeral"); sprintf(rs[i].addr, "*");
            i++;   rs[i] = r;                              sprintf(rs[i].port, "ephemeral");
            for (int j = 0; ; j++) {
                char *addr = sub_addr(r.addr, sizeof(r.addr) - 1, j);
                if (strncmp(addr, r.addr, sizeof(r.addr)) == 0) {
                    i++; rs[i] = r;                              sprintf(rs[i].addr, "*");
                    i++; rs[i] = r; sprintf(rs[i].cmdline, "*"); sprintf(rs[i].addr, "*");
                    i++; rs[i] = r; sprintf(rs[i].cmdline, "*"); memcpy(rs[i].addr, r.addr, sizeof(r.addr));
                    i++; rs[i] = r;                              memcpy(rs[i].addr, r.addr, sizeof(r.addr));
                    break;
                } else {
                    i++; rs[i] = r;                              sprintf(rs[i].addr, "*.%s", addr);
                    i++; rs[i] = r; sprintf(rs[i].cmdline, "*"); sprintf(rs[i].addr, "*.%s", addr);
                }
            }
        } else {
            i = 0; rs[i] = r;
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*");
        }
    }

    else if (strcmp(r.kind, "recv") == 0) {
        if (strcmp(r.proto, "tcp") == 0 || strcmp(r.proto, "udp") == 0) {
            i = 0; rs[i] = r;
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*");
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*"); sprintf(rs[i].port, "ephemeral");
            i++;   rs[i] = r;                              sprintf(rs[i].port, "ephemeral");
        } else {
            i = 0; rs[i] = r;
            i++;   rs[i] = r; sprintf(rs[i].cmdline, "*");
        }
    }

    else {
        ASSERT(0, "unknown kind2 [%s]\n", r.kind);
    }

    for (i32 i = 0; i < nrs; i++) {
        if (rs[i].kind[0] == 0) {
            break;
        }
        rule_t *match = NULL;
        char keybuf[sizeof(r)] = {0};
        i32 keysize = rule_key(&rs[i], keybuf, sizeof(keybuf));
        ASSERT(keysize > 0, "bad key: %d %s\n", keysize, keybuf);
        pthread_mutex_lock(&rules_lock); {
            MAP_FIND_INDEX(rules, keybuf, keysize);
            if (MAP_KEY(rules)) {
                match = MAP_VALUE(rules);
            }
        }; pthread_mutex_unlock(&rules_lock);
        if (match) {
            return match;
        }
    }
    return NULL;
}

pthread_mutex_t prompt_lock;
queue_t *prompt_q;
MAP_INIT(prompt, event_t*, 1<<16);

pthread_mutex_t nl_send_lock;

void log_decision(event_t *e, i32 response) {
    for (i32 i = 0; i < sizeof(e->cmdline); i++) {
        if (e->cmdline[i] == '\t') {
            e->cmdline[i] = ' ';
        }
    }

    char response_name[6] = {0};
    if (response == ALLOW) sprintf(response_name, "allow");
    else                   sprintf(response_name, "deny");

    char proto[32] = {0};
    if      (e->type == SOCK_DGRAM)  strcpy(proto, "udp");
    else if (e->type == SOCK_STREAM) strcpy(proto, "tcp");
    else if (e->type == SOCK_RAW)    strcpy(proto, "raw");
    else snprintf(proto, sizeof(proto) - 1, "socktype=%d", e->type);

    if (0 == strcmp(e->namebuf, "socket_recvmsg")) {
        struct sockaddr *sa = (struct sockaddr*)e->databuf;
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin_local = (struct sockaddr_in*)e->databuf;
            char port[10] = {0};
            sprintf(port, "ephemeral");
            if (ntohs(sin_local->sin_port) < EPHEMERAL_PORT_START) {
                sprintf(port, "%d", ntohs(sin_local->sin_port));
            }
            LOG("%s %s %d %s %s %s %s\n", response_name, "recv", e->pid, e->exe, port, proto, e->cmdline);
        } else {
            ASSERT(0, "these are always allowed in kernel\n");
        }
    } else if (0 == strcmp(e->namebuf, "socket_sendmsg")) {
        struct sockaddr *sa = (struct sockaddr*)e->databuf;
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin_remote = (struct sockaddr_in*)e->databuf;
            char addr_remote[18] = {0};
            ntoa(sin_remote->sin_addr, addr_remote, sizeof(addr_remote));
            if (!e->net_remote_domain[0]) {
                LOG("%s %s %d %s %s %d %s %s\n", response_name, "send", e->pid, e->exe, addr_remote, ntohs(sin_remote->sin_port), proto, e->cmdline);
            } else {
                LOG("%s %s %d %s %s %d %s %s\n", response_name, "send", e->pid, e->exe, e->net_remote_domain, ntohs(sin_remote->sin_port), proto, e->cmdline);
            }
        } else {
            ASSERT(0, "these are always allowed in kernel\n");
        }
    } else {
        ASSERT(0, "log decision unknown: %s\n", e->namebuf);
    }
}

static int dns_parse_callback(unsigned char *qname, int rr, const void *data, int len, const void *packet) { // based on musl @ 4100279825c17807bdabf1c128ba4e49a1dea406
    switch (rr) {
    case RR_A:
        if (len != 4)
            return -1;
        char *tmp;
        char addr[18] = {0};
        ntoa(*(struct in_addr*)data, addr, sizeof(addr));
        i32 size = sizeof(addr);
        pthread_mutex_lock(&dns_lock); {
            MAP_FIND_INDEX(dns, addr, size);
            if (!MAP_KEY(dns)) {
                MALLOC(tmp, size);
                memset(tmp, 0, size);
                strcpy(tmp, addr);
                MAP_SET_INDEX(dns, (u8*)tmp, size, char*);
            }
            if (MAP_VALUE(dns)) {
                free(MAP_VALUE(dns));
            }
            size = strlen((char*)qname) + 1;
            MALLOC(tmp, size);
            memset(tmp, 0, size);
            strcpy(tmp, (char*)qname);
            MAP_VALUE(dns) = tmp;
            LOG("dns %s %s\n", qname, addr);
        }; pthread_mutex_unlock(&dns_lock);
        return 0;
    default:
        return 0;
    }
}

void resolve_dns(event_t *e) {
    if (strcmp(e->namebuf, "socket_sendmsg") != 0)
        return;
    struct sockaddr *sa = (struct sockaddr*)e->databuf;
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin_remote = (struct sockaddr_in*)e->databuf;
        char addr[18] = {0};
        ntoa(sin_remote->sin_addr, addr, sizeof(addr));
        pthread_mutex_lock(&dns_lock); {
            MAP_FIND_INDEX(dns, addr, sizeof(addr));
            if (MAP_KEY(dns)) {
                ASSERT(MAP_VALUE(dns), "missing dns value\n");
                strncpy(e->net_remote_domain, MAP_VALUE(dns), sizeof(e->net_remote_domain));
            }
        }; pthread_mutex_unlock(&dns_lock);
    }
}

int sock_fd = 0;
struct sockaddr_nl src_addr = {0};
struct sockaddr_nl dest_addr = {0};

struct nlmsghdr *nlh_send;
struct msghdr msg_send = {0};
struct iovec iov_send = {0};
char msgbuf_send[NL_MAX_PAYLOAD] = {0};

struct nlmsghdr *nlh_recv;
struct msghdr msg_recv = {0};
struct iovec iov_recv = {0};
char msgbuf_recv[NL_MAX_PAYLOAD] = {0};

void *loop_netlink(void *vargp) {
    int res = 0;

    NL_INIT();

    // sent init message
    memset(msgbuf_send, 0, sizeof(msgbuf_send));
    NL_PREPARE_SEND(msgbuf_send);
    ASSERT(sendmsg(sock_fd, &msg_send, 0) >= 0, "failed to send init %d\n", errno);

    // vars
    i32 response;
    i32 size;
    char *head;

    // struct
    event_t *e;
    MALLOC(e, sizeof(*e));

    while (1) {

        // reset struct
        memset(e, 0, sizeof(*e));

        // recv and unpack message
        NL_PREPARE_RECV();
        res = recvmsg(sock_fd, &msg_recv, 0);
        if (res < 0) {
            if (errno != 11) // 11 is timeout
                LOG("error: recv %d\n", errno);
            continue;
        }
        head = NLMSG_DATA(nlh_recv);
        size = sizeof(e->id);      memcpy(&e->id,  head, size);    head += size;
        size = sizeof(e->pid);     memcpy(&e->pid, head, size);    head += size;
        size = sizeof(e->type);    memcpy(&e->type, head, size);   head += size;
        size = sizeof(e->namebuf); memcpy(e->namebuf, head, size); head += size;
        size = sizeof(e->exe);     memcpy(e->exe, head, size);     head += size;
        size = sizeof(e->cmdline); memcpy(e->cmdline, head, size); head += size;
        size = sizeof(e->databuf); memcpy(e->databuf, head, size); head += size;

        // we use tabs as a field separator, so sanitize all tabs
        TABS_TO_SPACES(e->exe);
        TABS_TO_SPACES(e->cmdline);

        // cmdline use nullbyte to separate argv[] elements, so sanitize all nullbytes
        ZEROS_TO_TABS(e->cmdline);

        // we use newlines as a field separator, so sanitize all newlines
        NEWLINES_TO_SPACES(e->cmdline);

        // resolve dns
        resolve_dns(e);

        // try to match a rule to the event
        rule_t *r = match_rule(e);

        // on hit, apply rule
        if (r) {

            // send response to kernel
            pthread_mutex_lock(&nl_send_lock); {
                if (strcmp(r->response, "allow") == 0) {
                    response = ALLOW;
                } else if (strcmp(r->response, "deny") == 0) {
                    response = DENY;
                } else {
                    ASSERT(0, "unknown response2 [%s]\n", r->response);
                }
                memset(msgbuf_send, 0, sizeof(msgbuf_send));
                head = msgbuf_send;
                size = sizeof(e->id);    memcpy(head, &e->id, size);    head += size;
                size = sizeof(response); memcpy(head, &response, size); head += size;
                NL_PREPARE_SEND(msgbuf_send);
                res = sendmsg(sock_fd, &msg_send, 0);
                log_decision(e, response);
            }; pthread_mutex_unlock(&nl_send_lock);
            if (res < 0) {
                LOG("error: send %d\n", errno);
            }

        }

        // on miss, enqueue for user prompt.
        else {
            i32 res;
            pthread_mutex_lock(&prompt_lock); {
                MAP_FIND_INDEX(prompt, &e->id, sizeof(e->id));
                // if id is already in known, skip. recv is idempotent to prompt queue.
                if (MAP_KEY(prompt)) {
                    pthread_mutex_unlock(&prompt_lock);
                    continue;
                }
                // malloc and copy event
                event_t *prompt_event;
                MALLOC(prompt_event, sizeof(*prompt_event));
                memcpy(prompt_event, e, sizeof(*e));
                // set event in prompt map by id
                i32 *key;
                MALLOC(key, sizeof(*key));
                *key = e->id;
                MAP_SET_INDEX(prompt, (u8*)key, sizeof(*key), event_t*);
                MAP_VALUE(prompt) = prompt_event;
                // enqueue id
                u8 *val;
                MALLOC(val, sizeof(e->id));
                memcpy(val, &e->id, sizeof(e->id));
                res = queue_put(prompt_q, val);
            }; pthread_mutex_unlock(&prompt_lock);

            // send DENY to kernel when prompt queue is full
            if (res != 0) {
                i32 res;
                pthread_mutex_lock(&nl_send_lock); {
                    memset(msgbuf_send, 0, sizeof(msgbuf_send));
                    char *head = msgbuf_send;
                    i32 size;
                    i32 response = DENY;
                    size = sizeof(e->id); memcpy(head, &e->id, size);    head += size;
                    size = sizeof(i32);   memcpy(head, &response, size); head += size;
                    NL_PREPARE_SEND(msgbuf_send);
                    res = sendmsg(sock_fd, &msg_send, 0);
                    fprintf(stdout, "prompt queue full: ");
                    log_decision(e, response);
                }; pthread_mutex_unlock(&nl_send_lock);
                if (res < 0) {
                    LOG("error: send %d\n", errno);
                }
            }

        }
    }
}

i32 prompt(event_t *e, char *payload, i32 size) {
    char outfile [64] = {0};
    sprintf(outfile, "/tmp/snitch_%d", e->id);
    char inbuf[4096] = {0};
    i32 n;
    if (foot_terminal) {
        // on alpine postmarketos sdm845 use foot as terminal
        n = sprintf(inbuf, "DISPLAY=:0 foot snitch-prompt '%.*s' %s 2>/dev/null", size, payload, outfile);
    } else {
        // on alpine x86_64 use st as terminal
        n = sprintf(inbuf, "DISPLAY=:0 st snitch-prompt '%.*s' %s 2>/dev/null", size, payload, outfile);
    }
    ASSERT(n < sizeof(inbuf), "prompt inbuf overflow\n");
    FILE *f = popen(inbuf, "r");
    if (!f) {
        LOG("prompt failure1: deny\n");
        return DENY;
    }
    char buf[1] = {0};
    while (fread(buf, 1, sizeof(buf), f)) {}
    i32 res = pclose(f);
    ZEROS_TO_TABS(inbuf);
    if (res != 0) {
        LOG("prompt failure2: deny %d\n", res);
        return DENY;
    }
    char outbuf[4096] = {0};
    f = fopen(outfile, "r");
    if (!f) {
        LOG("prompt failure3: deny\n");
        return DENY;
    }
    n = fread(outbuf, 1, sizeof(outbuf), f);
    ASSERT(n < sizeof(outbuf), "bad outfile read from prompt: %d\n", n);
    ASSERT(unlink(outfile) == 0, "failed to rm: %s\n", outfile);
    return add_rule(outbuf, sizeof(outbuf));
}

void do_prompt(result_t *result, event_t *e) {
    char payload1[4096] = {0};
    if (0 == strcmp(e->namebuf, "socket_recvmsg")) {
        struct sockaddr_in *sin_local = (struct sockaddr_in*)e->databuf;
        char proto[5] = {0};
        if (e->type == SOCK_DGRAM) {
            strcpy(proto, "udp");
        } else if (e->type == SOCK_STREAM) {
            strcpy(proto, "tcp");
        } else if (e->type == SOCK_RAW) {
            strcpy(proto, "raw");
        } else {
            snprintf(proto, sizeof(proto) - 1, "socktype=%d", e->type);
        }
        ASSERT(snprintf(payload1, sizeof(payload1) - 1, "recv\n%s\n%d\t%s\n%s", e->exe, ntohs(sin_local->sin_port), proto, e->cmdline) < sizeof(payload1), "payload1 overflow\n");
        result->response = prompt(e, payload1, sizeof(payload1));;
    }
    else if (0 == strcmp(e->namebuf, "socket_sendmsg")) {
        struct sockaddr_in *sin_remote = (struct sockaddr_in*)e->databuf;
        char addr_remote[18] = {0};
        ntoa(sin_remote->sin_addr, addr_remote, sizeof(addr_remote));
        char *addr = addr_remote;
        if (e->net_remote_domain[0] != 0) {
            addr = e->net_remote_domain;
        }
        char port[6] = {0};
        snprintf(port, sizeof(port), "%d", ntohs(sin_remote->sin_port));
        char proto[5] = {0};
        if (e->type == SOCK_DGRAM) {
            strcpy(proto, "udp");
        } else if (e->type == SOCK_STREAM) {
            strcpy(proto, "tcp");
        } else if (e->type == SOCK_RAW) {
            strcpy(proto, "raw");
        } else {
            snprintf(proto, sizeof(proto) - 1, "socktype=%d", e->type);
        }
        ASSERT(snprintf(payload1, sizeof(payload1) - 1, "send\n%s\n%s\t%s\t%s\n%s", e->exe, addr, port, proto, e->cmdline) < sizeof(payload1), "payload1 overflow\n");
        result->response = prompt(e, payload1, sizeof(payload1));
    }
    else {
        ASSERT(0, "bad name: %s\n", e->namebuf);
    }
}

void *loop_rules_writer(void *vargp) {
    while (1) {

        usleep(1000 * 1000);

        pthread_mutex_lock(&rules_lock); {
            if (!rules_file_needs_write) {
                pthread_mutex_unlock(&rules_lock);
                continue;
            }
        }; pthread_mutex_unlock(&rules_lock);

        ARRAY_INIT(rule_lines, char*);

        pthread_mutex_lock(&rules_lock); {
            for (i32 i = 0; i < MAP_SIZE(rules); i++) {
                if (MAP_VALUES(rules)[i] != NULL && strncmp(MAP_VALUES(rules)[i]->duration, "forever", 7) == 0) {
                    char buf[2048] = {0};
                    i32 size = rule_format(MAP_VALUES(rules)[i], buf, sizeof(buf));
                    char *line;
                    MALLOC(line, size + 1);
                    memset(line, 0, size + 1);
                    strncpy(line, buf, size);
                    ARRAY_APPEND(rule_lines, line, char*);
                }
            }
        }; pthread_mutex_unlock(&rules_lock);

        qsort(rule_lines, ARRAY_SIZE(rule_lines), sizeof(char*), sortcmp);

        pthread_mutex_lock(&rules_file_lock); {
            FILE *f = fopen(rules_file, "w");
            ASSERT(f, "failed to open rules_file: %s\n", rules_file);
            for (i32 i = 0; i < ARRAY_SIZE(rule_lines); i++) {
                i32 size = strlen(rule_lines[i]);
                ASSERT(fwrite(rule_lines[i], 1, size, f) == size, "short write on rules file\n");
                ASSERT(fwrite("\n", 1, 1, f) == 1, "short write on rules file newline\n");
            }
            ASSERT(fclose(f) == 0, "failed to close rules file on write\n");
            rules_file_needs_write = 0;
        }; pthread_mutex_unlock(&rules_file_lock);

        LOG("write rules file\n");

        free(rule_lines);

    }
}

void *loop_rules_expirer(void *vargp) {
  while (1) {

      usleep(1000 * 1000);

      pthread_mutex_lock(&rules_lock); {

          for (i32 i = 0; i < MAP_SIZE(rules); i++) {
              rule_t *r = MAP_VALUES(rules)[i];
              char *key = (char*)MAP_KEYS(rules)[i];
              if (r && key) {
                  if ((strncmp(r->duration, "1-minute", sizeof(r->duration)) == 0 && unix_seconds() - r->creation > 60) ||
                      (strncmp(r->duration, "24-hour", sizeof(r->duration)) == 0 && unix_seconds() - r->creation > 60 * 60 * 24))
                  {
                      LOG("expire-rule %s\n", key);
                      MAP_UNSET_INDEX(rules, key, MAP_SIZES(rules)[i]);
                      free(MAP_VALUES(rules)[i]);
                      MAP_VALUES(rules)[i] = NULL;
                  }
              }
          }

      }; pthread_mutex_unlock(&rules_lock);

  }
}

void *loop_rules_reader(void *vargp) {
    while (1) {
        struct stat st;

        pthread_mutex_lock(&rules_file_lock); {

            if (stat(rules_file, &st) == 0) {
                i64 mtime = st.st_mtim.tv_sec * (i64)1000000 + st.st_mtim.tv_nsec;
                if (rules_file_mtime == mtime) {
                    pthread_mutex_unlock(&rules_file_lock);
                    usleep(1000 * 1000);
                    continue;
                }
                rules_file_mtime = mtime;

                pthread_mutex_lock(&rules_lock); {

                    for (i32 i = 0; i < MAP_SIZE(rules); i++) {
                        rule_t *r = MAP_VALUES(rules)[i];
                        if (r) {
                            r->meta = 1;
                        }
                    }

                    char buf[2048] = {0};
                    char *head = buf;
                    FILE *f = fopen(rules_file, "r");
                    ASSERT(f, "failed to open rules files: %s\n", rules_file);
                    i32 stop = 0;
                    while (!stop) {
                        if (!fread(head, 1, 1, f)) {
                            stop = 1;
                            fclose(f);
                        }
                        i32 size = head - buf;
                        ASSERT(size < sizeof(buf) - 1, "rule line too long");
                        if (size && (stop || *head == '\n')) {
                            *head = 0;
                            rule_t *r = rule_parse(buf, size);
                            if (r) {
                                char keybuf[sizeof(*r)] = {0};
                                i32 keysize = rule_key(r, keybuf, sizeof(keybuf));
                                MAP_FIND_INDEX(rules, keybuf, keysize);
                                if (!MAP_KEY(rules)) {
                                    char *key;
                                    MALLOC(key, keysize + 1);
                                    memset(key, 0, keysize + 1);
                                    strncpy(key, keybuf, keysize);
                                    MAP_SET_INDEX(rules, (u8*)key, keysize, rule_t*);
                                    LOG("load-rule %s\n", buf);
                                }
                                if (MAP_VALUE(rules)) {
                                    u8 meta = MAP_VALUE(rules)->meta;
                                    MAP_VALUE(rules)->meta = 0;
                                    if (!rule_equal(r, MAP_VALUE(rules))) {
                                        LOG("update-rule %s\n", buf);
                                    }
                                    MAP_VALUE(rules)->meta = meta;
                                    free(MAP_VALUE(rules));
                                }
                                MAP_VALUE(rules) = r;
                            }
                            memset(buf, 0, sizeof(buf));
                            head = buf;
                        } else {
                            head++;
                        }
                    }

                    for (i32 i = 0; i < MAP_SIZE(rules); i++) {
                        rule_t *r = MAP_VALUES(rules)[i];
                        char *key = (char*)MAP_KEYS(rules)[i];
                        if (r && r->meta == 1 && key && strncmp(r->duration, "forever", sizeof(r->duration)) == 0) {
                            LOG("delete-rule %s\n", key);
                            MAP_UNSET_INDEX(rules, key, MAP_SIZES(rules)[i]);
                            free(MAP_VALUES(rules)[i]);
                            MAP_VALUES(rules)[i] = NULL;
                        }
                    }

                }; pthread_mutex_unlock(&rules_lock);

            }
        }; pthread_mutex_unlock(&rules_file_lock);
    }
}

void *loop_prompt(void *vargp) {
    while (1) {
        i32 id;
        event_t *e;

        // dequeue prompt id and lookup value in prompt map
        pthread_mutex_lock(&prompt_lock); {
            u8 *val = queue_get(prompt_q);
            if (!val) {
                pthread_mutex_unlock(&prompt_lock);
                usleep(1000);
                continue;
            }
            id = *(i32*)val;
            free(val);
            MAP_FIND_INDEX(prompt, &id, sizeof(id));
            ASSERT(MAP_KEY(prompt), "no key in map\n");
            e = MAP_VALUE(prompt);
        }; pthread_mutex_unlock(&prompt_lock);

        result_t rs = {0};
        result_t *result = &rs;
        result->response = -1;
        result->id = id;

        // check rule again since rules can change while enqueued
        rule_t *rule = match_rule(e);

        if (rule) {
            if (strcmp(rule->response, "allow") == 0) {
                result->response = ALLOW;
            } else if (strcmp(rule->response, "deny") == 0) {
                result->response = DENY;
            } else {
                ASSERT(0, "bad rule response [%s]\n", rule->response);
            }
        }

        else {
            do_prompt(result, e);
        }

        // send response to kernel
        i32 res;
        pthread_mutex_lock(&nl_send_lock); {
            memset(msgbuf_send, 0, sizeof(msgbuf_send));
            char *head = msgbuf_send;
            int size;
            size = sizeof(id);               memcpy(head, &id, size);               head += size;
            size = sizeof(result->response); memcpy(head, &result->response, size); head += size;
            NL_PREPARE_SEND(msgbuf_send);
            res = sendmsg(sock_fd, &msg_send, 0);
            log_decision(e, result->response);
        }; pthread_mutex_unlock(&nl_send_lock);

        // free value from prompt map
        pthread_mutex_lock(&prompt_lock); {
            MAP_UNSET_INDEX(prompt, &id, sizeof(id));
            free(MAP_VALUE(prompt));
            MAP_VALUE(prompt) = NULL;
        }; pthread_mutex_unlock(&prompt_lock);

        if (res < 0) {
            LOG("error: send %d\n", errno);
            continue;
        }
    }
}

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    unsigned char *buffer = NULL;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    unsigned int id = ntohl(ph->packet_id);
    int size = nfq_get_payload(nfad, &buffer);
    if (size > 0) {
        packet_t p = {0};
        if (0 == parse_ipv4(buffer, size, &p)) {
            if (p.sport == 53) {
                dns_parse(buffer + p.offset, p.size, dns_parse_callback);
            }
        }
    }
    nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return 0;
}

void *loop_nfq(void *vargp) {
    nftables_init();
    struct nfq_handle *h = nfq_open();
    ASSERT(h != NULL, "failed to open nfq\n");
    ASSERT(nfq_unbind_pf(h, AF_INET) >= 0, "failed to unbind inet %d\n", errno);
    ASSERT(nfq_bind_pf(h, AF_INET) >= 0, "failed to bind inet %d\n", errno);
    struct nfq_q_handle *qh = nfq_create_queue(h, NFQ_QUEUE, &nf_callback, (void*)((uintptr_t)unix_nano()));
    ASSERT(qh != NULL, "failed to create queue\n");
    ASSERT(nfq_set_queue_maxlen(qh, NFQ_QUEUE_SIZE) >= 0, "failed to set queue len\n");
    ASSERT(nfq_set_mode(qh, NFQNL_COPY_PACKET, NFQ_PACKET_SIZE) >= 0, "failed to set mode\n");
    int fd = nfq_fd(h);
    ASSERT(nfnl_rcvbufsiz(nfq_nfnlh(h), NFQ_TOTAL_SIZE) >= 0, "failed to set rcvbuf size\n");
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
    while (1) {
        memset(buf, 0, sizeof(buf));
        rcvd = recv(fd, buf, sizeof(buf), 0);
        ASSERT(rcvd >= 0, "nfq failed: errno: %d\n", errno);
        nfq_handle_packet(h, buf, rcvd);
    }
    return NULL;
}

void thread(void *(*func)(void *)) {
    pthread_t t;
    pthread_create(&t, NULL, func, NULL);
}

void which_terminal() {
    FILE *f = popen("which foot", "r");
    ASSERT(f, "failed to which foot\n");
    char buf[1] = {0};
    while (fread(buf, 1, sizeof(buf), f)) {}
    foot_terminal = pclose(f) == 0;
    if (foot_terminal) {
        setenv("SNITCH_PROMPT_INTERVAL", "0.05", 1);
    }
}

int main(int argc, char **argv) {

    which_terminal();

    strcpy(home, getenv("HOME"));
    ASSERT(sprintf(rules_file, "%s/.snitch.rules", home) > 0, "failed to sprintf rules_file\n");
    LOG("rules_file: %s\n", rules_file);

    i32 size = 1<<16;
    prompt_q = queue_init(size);

    MAP_ALLOC(dns, char*);
    MAP_ALLOC(rules, rule_t*);
    MAP_ALLOC(prompt, event_t*);

    thread(loop_nfq);
    thread(loop_prompt);
    thread(loop_rules_writer);
    thread(loop_rules_reader);
    thread(loop_rules_expirer);
    thread(loop_netlink);

    // block main thread
    while (1)
        usleep(1000*1000);

}
