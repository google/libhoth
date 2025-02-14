// Copyright 2022 Google LLC
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

#include "progress.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static struct timespec ts_now() {
  struct timespec result;
  int rv = clock_gettime(CLOCK_MONOTONIC, &result);
  if (rv != 0) {
    perror("clock_gettime(CLOCK_MONOTONIC) failed");
    abort();
  }
  return result;
}

static struct timespec ts_subtract(struct timespec a, struct timespec b) {
  if (a.tv_nsec > b.tv_nsec) {
    return (struct timespec){
        .tv_sec = (a.tv_sec - b.tv_sec),
        .tv_nsec = (a.tv_nsec - b.tv_nsec),
    };
  } else {
    return (struct timespec){
        .tv_sec = (a.tv_sec - b.tv_sec) - 1,
        .tv_nsec = a.tv_nsec + 1000000000 - b.tv_nsec,
    };
  }
}
static uint64_t ts_milliseconds(struct timespec ts) {
  return ((uint64_t)ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

struct stderr_progress {
  struct libhoth_progress progress;
  struct timespec start_time;
  const char* action_title;
};

static void libhoth_progress_stderr_func(void* param, uint64_t numerator,
                                       uint64_t denominator) {
  struct stderr_progress* self = (struct stderr_progress*)param;
  if (isatty(STDERR_FILENO)) {
    uint64_t duration_ms =
        ts_milliseconds(ts_subtract(ts_now(), self->start_time));
    if (duration_ms == 0) {
      // avoid divide-by-zero
      duration_ms = 1;
    }
    fprintf(
        stderr,
        "%s: % 3.0f%% - %lldkB / %lldkB  %lld kB/sec; %.1f s remaining     %s",
        self->action_title, ((double)numerator / (double)denominator) * 100.0,
        (long long)(numerator / 1000), (long long)(denominator / 1000),
        (long long)(numerator / duration_ms),
        (double)(denominator - numerator) * (double)duration_ms * 0.001 /
            (double)numerator,
        numerator == denominator ? "\n" : "\r");
  }
}

void libhoth_progress_stderr_init(struct libhoth_progress_stderr* progress,
                                const char* action_title) {
  progress->progress.param = progress;
  progress->progress.func = libhoth_progress_stderr_func;
  progress->start_time = ts_now();
  progress->action_title = action_title;
}
