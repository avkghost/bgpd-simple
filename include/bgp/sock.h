#pragma once
#include <stdint.h>
#include <netinet/in.h>

int sock_set_nonblock(int fd);
int sock_set_nodelay(int fd);
int sock_connect_nonblock(struct in_addr dst, uint16_t port);
/*
 * Create a non-blocking TCP listen socket bound to the given port on all
 * interfaces (INADDR_ANY).  Returns the fd on success, -1 on error.
 * Caller must call accept() when the fd becomes readable.
 */
int sock_create_listen(uint16_t port);
