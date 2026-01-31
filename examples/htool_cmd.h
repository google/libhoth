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

#ifndef LIBHOTH_EXAMPLES_HTOOL_CMD_H_
#define LIBHOTH_EXAMPLES_HTOOL_CMD_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum htool_param_type {
  HTOOL_PARAM_END = 0,

  // A flag with a value (like --pos=35)
  HTOOL_FLAG_VALUE,

  // A flag that can be true or false (like --verify)
  HTOOL_FLAG_BOOL,

  // A positional param (like <infile>)
  HTOOL_POSITIONAL,
};

struct htool_param {
  enum htool_param_type type;
  const char ch;
  const char* name;
  const char* default_value;
  const char* desc;
};

struct htool_invocation;

struct htool_cmd {
  const char* const* verbs;
  const char* const* alias;
  const char* desc;
  const struct htool_param* params;
  int (*func)(const struct htool_invocation*);
  const char* deprecation_message;
};

struct htool_invocation {
  const struct htool_cmd* cmd;

  // The argument values in the same order as the cmd parameters.
  const char** args;
};

bool htool_has_param(const struct htool_invocation* inv, const char* name);

int htool_get_param_bool(const struct htool_invocation* inv, const char* name,
                         bool* value);
int htool_get_param_u32(const struct htool_invocation* inv, const char* name,
                        uint32_t* value);
int htool_get_param_string(const struct htool_invocation* inv, const char* name,
                           const char** value);
int htool_get_param_u32_or_fourcc(const struct htool_invocation* inv,
                                  const char* name, uint32_t* value);

struct htool_invocation* htool_global_flags(void);

int htool_main(const struct htool_param* global_flags,
               const struct htool_cmd* cmds, int argc, const char* const* argv);

// Helper function to parse time string with units (s, ms, us) into microseconds
// Returns -1 on error.
int64_t parse_time_string_us(const char* time_str);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_CMD_H_
