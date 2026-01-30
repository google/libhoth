// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

uint64_t libhoth_get_monotonic_ms() {
  struct timespec ts;
  int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (ret != 0) {
    perror("clock_gettime failed");
    // Very unlikely to happen and probably not
    // possible to recover from this.
    exit(ret);
  }
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint32_t libhoth_prng_seed() {
  // TODO: Can we just use rand() here?
  struct timespec ts;
  int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (ret != 0) {
    perror("clock_gettime failed");
    // Very unlikely to happen and probably not
    // possible to recover from this.
    exit(ret);
  }
  return ts.tv_sec ^ ts.tv_nsec ^ getpid();
}

int libhoth_force_write(int fd, const void* buf, size_t count) {
  const char* cbuf = buf;
  while (count > 0) {
    ssize_t bytes_written = write(fd, cbuf, count);
    if (bytes_written < 0) {
      return errno;
    }
    cbuf += bytes_written;
    count -= bytes_written;
  }
  return 0;
}
