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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// This function is defined as weak to allow unit tests to override it
// with a mock implementation for deterministic time control.
__attribute__((weak)) struct timespec libhoth_progress_get_time(void) {
  struct timespec result;
  int rv = clock_gettime(CLOCK_MONOTONIC, &result);
  if (rv != 0) {
    perror("clock_gettime(CLOCK_MONOTONIC) failed");
    abort();
  }
  return result;
}

static struct timespec ts_subtract(struct timespec a, struct timespec b) {
  if (a.tv_nsec >= b.tv_nsec) {
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

static void libhoth_progress_stderr_func(void* param, const uint64_t current,
                                         const uint64_t total) {
  struct libhoth_progress_stderr* const self =
      (struct libhoth_progress_stderr*)param;

  if (!self->is_tty) {
    return;
  }

  // Calculate 1% of the total size as the minimum increment for reporting.
  const uint64_t one_percent_threshold = (total < 100) ? 1 : (total / 100);

  const bool is_start = (current == 0);
  const bool is_end = (current == total);
  const bool has_sufficient_progress =
      (current >= self->last_reported_val + one_percent_threshold);

  if (!is_start && !is_end && !has_sufficient_progress) {
    return;
  }

  self->last_reported_val = current;

  struct timespec now = libhoth_progress_get_time();

  uint64_t duration_ms = ts_milliseconds(ts_subtract(now, self->start_time));
  if (duration_ms == 0) {
    // avoid divide-by-zero
    duration_ms = 1;
  }

  const double progress_pct = total > 0 ? (100.0 * current) / total : 100.0;
  const double speed_kib_s = (current / 1024.0) / (duration_ms / 1000.0);
  double remaining_s = 0;
  if (speed_kib_s > 0) {
    remaining_s = ((total - current) / 1024.0) / speed_kib_s;
  }

  fprintf(stderr,
          "%s: %3.0f%% - %" PRIu64 "KiB / %" PRIu64
          "KiB  %.0f KiB/sec; %.0f s remaining%s",
          self->action_title, progress_pct, current / 1024, total / 1024,
          speed_kib_s, remaining_s, is_end ? "\033[K\n" : "\033[K\r");
}

void libhoth_progress_stderr_init(struct libhoth_progress_stderr* progress,
                                  const char* action_title) {
  progress->progress.param = progress;
  progress->progress.func = libhoth_progress_stderr_func;
  progress->start_time = libhoth_progress_get_time();
  progress->action_title = action_title;
  progress->last_reported_val = 0;
  progress->is_tty = isatty(STDERR_FILENO);
}
