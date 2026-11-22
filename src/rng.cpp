#include "rng.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/random.h>

void os_random(void* buf, size_t len) {
  uint8_t* p = static_cast<uint8_t*>(buf);
  while (len) {
    ssize_t r = getrandom(p, len, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      perror("getrandom");
      abort();
    }
    p += r;
    len -= (size_t)r;
  }
}

void secure_zero(void* buf, size_t len) {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(buf);
  while (len--) *p++ = 0;
}
