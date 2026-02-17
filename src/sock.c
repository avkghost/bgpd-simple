#include "bgp/sock.h"
#include "bgp/log.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int sock_set_nonblock(int fd){
  int fl = fcntl(fd, F_GETFL, 0);
  if(fl < 0) return -1;
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int sock_set_nodelay(int fd){
  int yes = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
}

static void sock_set_cloexec(int fd){
  int flags = fcntl(fd, F_GETFD);
  if(flags >= 0){
    (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
}

int sock_connect_nonblock(struct in_addr dst, uint16_t port){
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;

  sock_set_cloexec(fd);

  if(sock_set_nonblock(fd) < 0){
    close(fd);
    return -1;
  }

  (void)sock_set_nodelay(fd); // not fatal if it fails

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr = dst;
  sa.sin_port = htons(port);

  int rc = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
  if(rc == 0) return fd;
  if(rc < 0 && errno == EINPROGRESS) return fd;

  close(fd);
  return -1;
}

int sock_create_listen(uint16_t port){
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;

  sock_set_cloexec(fd);

  /* Allow rapid re-bind after daemon restart */
  int yes = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port        = htons(port);

  if(bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0){
    close(fd);
    return -1;
  }

  if(listen(fd, 16) < 0){
    close(fd);
    return -1;
  }

  if(sock_set_nonblock(fd) < 0){
    close(fd);
    return -1;
  }

  return fd;
}
