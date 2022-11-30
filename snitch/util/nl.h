#pragma once

#define NL_MAX_PAYLOAD 2048

#define NL_USER 31

#define NL_INIT()                                                                                                        \
    nlh_send = malloc(NLMSG_SPACE(NL_MAX_PAYLOAD));                                                                     \
    nlh_recv = malloc(NLMSG_SPACE(NL_MAX_PAYLOAD));                                                                      \
    /* */                                                                                                               \
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NL_USER);                                                                    \
    ASSERT(sock_fd > 0, "failed to get nl socket %d\n", sock_fd);                                                        \
    /* */                                                                                                                \
    memset(&src_addr, 0, sizeof(src_addr));                                                                                \
    src_addr.nl_family = AF_NETLINK;                                                                                    \
    src_addr.nl_pid = getpid();                                                                                            \
    src_addr.nl_groups = 0;                                                                                                \
    ASSERT(0 == bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)), "failed to bind %d\n", errno);            \
    /* */                                                                                                                \
    memset(&dest_addr, 0, sizeof(dest_addr));                                                                            \
    dest_addr.nl_family = AF_NETLINK;                                                                                    \
    dest_addr.nl_pid = 0;                                                                                                \
    dest_addr.nl_groups = 0;

#define NL_PREPARE_RECV()                                           \
    memset(nlh_recv, 0, NLMSG_SPACE(NL_MAX_PAYLOAD));               \
    nlh_recv->nlmsg_len = NLMSG_SPACE(NL_MAX_PAYLOAD);              \
    nlh_recv->nlmsg_pid = getpid();                                 \
    nlh_recv->nlmsg_flags = 0;                                      \
    memcpy(NLMSG_DATA(nlh_recv), msgbuf_recv, sizeof(msgbuf_recv)); \
    memset(&iov_recv, 0, sizeof(iov_recv));                         \
    iov_recv.iov_base = (void *)nlh_recv;                           \
    iov_recv.iov_len = nlh_recv->nlmsg_len;                         \
    memset(&msg_recv, 0, sizeof(msg_recv));                         \
    msg_recv.msg_name = (void *)&dest_addr;                         \
    msg_recv.msg_namelen = sizeof(dest_addr);                       \
    msg_recv.msg_iov = &iov_recv;                                   \
    msg_recv.msg_iovlen = 1;

#define NL_PREPARE_SEND(msgbuf)                             \
    memset(nlh_send, 0, NLMSG_SPACE(NL_MAX_PAYLOAD));        \
    nlh_send->nlmsg_len = NLMSG_SPACE(NL_MAX_PAYLOAD);        \
    nlh_send->nlmsg_pid = getpid();                         \
    nlh_send->nlmsg_flags = 0;                              \
    memcpy(NLMSG_DATA(nlh_send), msgbuf, sizeof(msgbuf));   \
    memset(&iov_send, 0, sizeof(iov_send));                 \
    iov_send.iov_base = (void *)nlh_send;                   \
    iov_send.iov_len = nlh_send->nlmsg_len;                 \
    memset(&msg_send, 0, sizeof(msg_send));                 \
    msg_send.msg_name = (void *)&dest_addr;                 \
    msg_send.msg_namelen = sizeof(dest_addr);               \
    msg_send.msg_iov = &iov_send;                           \
    msg_send.msg_iovlen = 1;
