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

#include "htool_cmd.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "git_version.h"

static int matches_verbs(const char* const* verbs, int argc,
                         const char* const* argv) {
  for (int i = 0; i < argc; i++) {
    if (!verbs[i]) {
      return i;
    }
    if (strcmp(argv[i], verbs[i]) != 0) {
      return 0;
    }
  }
  if (!verbs[argc]) {
    return argc;
  } else {
    return 0;
  }
}

static const struct htool_cmd* find_command(const struct htool_cmd* cmds,
                                            int argc, const char* const* argv,
                                            int* num_verb_words) {
  for (int i = 0; cmds[i].verbs; i++) {
    int consume = matches_verbs(cmds[i].verbs, argc, argv);
    if (consume) {
      *num_verb_words = consume;
      return &cmds[i];
    }
    if (cmds[i].alias) {
      consume = matches_verbs(cmds[i].alias, argc, argv);
      if (consume) {
        *num_verb_words = consume;
        return &cmds[i];
      }
    }
  }
  return NULL;
}

static void print_flags(const struct htool_param* params) {
  for (size_t i = 0; params[i].type != HTOOL_PARAM_END; i++) {
    const struct htool_param* param = &params[i];
    if (param->type == HTOOL_POSITIONAL) {
      continue;
    }
    fprintf(stderr, "  ");
    if (param->ch) {
      fprintf(stderr, "-%c ", param->ch);
    }
    fprintf(stderr, "--%s", param->name);
    if (param->default_value) {
      fprintf(stderr, " (default: \"%s\")", param->default_value);
    }
    fprintf(stderr, "\n");
    if (param->desc) {
      fprintf(stderr, "        %s\n", param->desc);
    }
  }
}

static void print_usage(const struct htool_cmd* cmd) {
  fprintf(stderr, "Usage: ");
  for (size_t i = 0; cmd->verbs[i]; i++) {
    fprintf(stderr, "%s ", cmd->verbs[i]);
  }
  for (size_t i = 0; cmd->params[i].type != HTOOL_PARAM_END; i++) {
    const struct htool_param* param = &cmd->params[i];
    if (param->type == HTOOL_POSITIONAL) {
      fprintf(stderr, "<%s> ", param->name);
    }
  }
  fprintf(stderr, "\n");
  print_flags(cmd->params);
}

static void enumerate_cmds(const struct htool_cmd* cmds) {
  fprintf(stderr,
          "Available subcommands: (append --help to subcommand for details)\n");
  for (size_t i = 0; cmds[i].verbs; i++) {
    if (cmds[i].deprecation_message == NULL) {  // Hide deprecated commands
      fprintf(stderr, " ");
      for (size_t j = 0; cmds[i].verbs[j]; j++) {
        fprintf(stderr, " %s", cmds[i].verbs[j]);
      }
      fprintf(stderr, " - %s\n", cmds[i].desc);
    }
  }
}

static bool flag_name_equals(const char* a, const char* b) {
  for (size_t i = 0;; i++) {
    if (a[i] == '\0' || a[i] == '=') {
      return b[i] == '\0' || b[i] == '=';
    }
    if (b[i] == '\0' || b[i] == '=') {
      return false;
    }
    if (a[i] != b[i]) {
      return false;
    }
  }
}

struct param_info {
  const struct htool_param* param;
  size_t index;
};

static int find_param_by_name(const struct htool_param* params,
                              const char* name, struct param_info* info) {
  for (size_t i = 0; params[i].type != HTOOL_PARAM_END; i++) {
    if (strcmp(params[i].name, name) == 0) {
      *info = (struct param_info){
          .param = &params[i],
          .index = i,
      };
      return 0;
    }
  }
  return -1;
}

static const char* get_param(const struct htool_invocation* inv,
                             const char* name) {
  struct param_info param_info;
  int rv = find_param_by_name(inv->cmd->params, name, &param_info);
  if (rv) {
    fprintf(stderr, "INTERNAL ERROR: asked for non-registered argument %s\n",
            name);
    return NULL;
  }
  if (inv->args[param_info.index]) {
    return inv->args[param_info.index];
  }
  return param_info.param->default_value;
}

bool htool_has_param(const struct htool_invocation* inv, const char* name) {
  return get_param(inv, name) != NULL;
}

static const char* get_param_required(const struct htool_invocation* inv,
                                      const char* name) {
  const char* result = get_param(inv, name);
  if (result) {
    return result;
  }
  struct param_info param_info;
  int rv = find_param_by_name(inv->cmd->params, name, &param_info);
  if (rv) {
    goto err;
  }
  if (param_info.param->type == HTOOL_POSITIONAL) {
    fprintf(stderr, "Unspecified positional argument <%s>\n",
            param_info.param->name);
    goto err;
  }
  if (param_info.param->type == HTOOL_FLAG_VALUE ||
      param_info.param->type == HTOOL_FLAG_BOOL) {
    fprintf(stderr, "Unspecified required flag: --%s", param_info.param->name);
    if (param_info.param->ch) {
      fprintf(stderr, " (or -%c)", param_info.param->ch);
    }
    fprintf(stderr, "\n");
    goto err;
  }

  fprintf(stderr, "INTERNAL ERROR: param %s has unknown type\n",
          param_info.param->name);
err:
  print_usage(inv->cmd);
  return NULL;
}

int htool_get_param_string(const struct htool_invocation* inv, const char* name,
                           const char** value) {
  const char* s = get_param_required(inv, name);
  if (!s) {
    return -1;
  }
  *value = s;
  return 0;
}

int htool_get_param_bool(const struct htool_invocation* inv, const char* name,
                         bool* value) {
  const char* str_value = get_param_required(inv, name);
  if (!str_value) {
    return -1;
  }
  if (strcmp(str_value, "true") == 0 || strcmp(str_value, "1") == 0 ||
      strcmp(str_value, "TRUE") == 0) {
    *value = true;
    return 0;
  }
  if (strcmp(str_value, "false") == 0 || strcmp(str_value, "0") == 0 ||
      strcmp(str_value, "FALSE") == 0) {
    *value = false;
    return 0;
  }
  fprintf(stderr, "Unable to parse %s=\"%s\" as bool\n", name, str_value);
  return -1;
}

static int parse_u32(const char* s, uint32_t* value) {
  unsigned long lval;
  char* endptr = NULL;

  if (s[0] == '0' && s[1] == 'x' && s[2] != '\0') {
    lval = strtoul(&s[2], &endptr, 16);
  } else {
    lval = strtoul(s, &endptr, 10);
  }
  if (s[0] != '\0' && endptr && *endptr == '\0') {
    *value = (uint32_t)lval;
    return 0;
  }
  return -1;
}

int htool_get_param_u32(const struct htool_invocation* inv, const char* name,
                        uint32_t* value) {
  const char* s = get_param_required(inv, name);
  if (!s) {
    return -1;
  }
  int status = parse_u32(s, value);
  if (status) {
    fprintf(stderr, "Unable to parse %s=\"%s\" as u32\n", name, s);
    return -1;
  }
  return 0;
}

int htool_get_param_u32_or_fourcc(const struct htool_invocation* inv,
                                  const char* name, uint32_t* value) {
  const char* s = get_param_required(inv, name);
  if (!s) {
    return -1;
  }
  int status = parse_u32(s, value);
  if (!status) {
    return 0;
  }
  if (strlen(s) == 4) {
    *value = ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |
             ((uint32_t)s[2] << 8) | ((uint32_t)s[3] << 0);
    return 0;
  }
  fprintf(stderr, "Unable to parse %s=\"%s\" as u32 or fourcc\n", name, s);
  return -1;
}

static int find_positional_param(const struct htool_param* params, int index,
                                 struct param_info* info) {
  int num_positional_params_seen = 0;
  for (size_t i = 0; params[i].type != HTOOL_PARAM_END; i++) {
    if (params[i].type == HTOOL_POSITIONAL) {
      if (num_positional_params_seen == index) {
        info->param = &params[i];
        info->index = i;
        return 0;
      }
      num_positional_params_seen++;
    }
  }
  return -1;
}

static int find_flag(const struct htool_param* params, const char* s,
                     struct param_info* info, const char** value) {
  if (s[0] != '-') {
    return -1;
  }
  if (s[1] != '-') {
    if (s[1] == '\0') {
      return -1;
    }
    for (size_t i = 0; params[i].type != HTOOL_PARAM_END; i++) {
      if ((params[i].type == HTOOL_FLAG_VALUE ||
           params[i].type == HTOOL_FLAG_BOOL) &&
          params[i].ch == s[1]) {
        *value = s[2] ? &s[2] : NULL;
        if (!*value && params[i].type == HTOOL_FLAG_BOOL) {
          *value = "true";
        }
        info->param = &params[i];
        info->index = i;
        return 0;
      }
    }
  }
  const char* flag_name = &s[2];
  for (size_t i = 0; params[i].type != HTOOL_PARAM_END; i++) {
    if (flag_name[0] == 'n' && flag_name[1] == 'o' &&
        params[i].type == HTOOL_FLAG_BOOL &&
        strcmp(params[i].name, &flag_name[2]) == 0) {
      *value = "false";
      info->param = &params[i];
      info->index = i;
      return 0;
    }
    if ((params[i].type == HTOOL_FLAG_VALUE ||
         params[i].type == HTOOL_FLAG_BOOL) &&
        flag_name_equals(params[i].name, flag_name)) {
      const char* value_str = strstr(flag_name, "=");
      *value = value_str ? (value_str + 1) : NULL;
      if (!*value && params[i].type == HTOOL_FLAG_BOOL) {
        *value = "true";
      }
      info->param = &params[i];
      info->index = i;
      return 0;
    }
  }
  return -1;
}

static int fill_cmd_invocation(struct htool_invocation* inv,
                               const struct htool_cmd* cmd, int argc,
                               const char* const* argv) {
  inv->cmd = cmd;
  int num_params = 0;
  int positional_param_index = 0;
  for (; cmd->params[num_params].type != HTOOL_PARAM_END; num_params++);
  inv->args = calloc(num_params, sizeof(const char*));
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      if (strcmp(argv[i], "--help") == 0) {
        print_usage(inv->cmd);
        return -1;
      }
      struct param_info param_info;
      const char* value;
      int rv = find_flag(cmd->params, argv[i], &param_info, &value);
      if (rv) {
        fprintf(stderr, "Unknown flag %s\n", argv[i]);
        return -1;
      }
      if (param_info.param->type == HTOOL_FLAG_VALUE && !value) {
        if (i + 1 == argc || argv[i + 1][0] == '-') {
          fprintf(stderr, "Missing value for flag %s\n", argv[i]);
          return -1;
        }
        value = argv[i + 1];

        // Don't process the flag value
        i++;
      }
      inv->args[param_info.index] = value;
    } else {
      struct param_info param_info;
      int rv = find_positional_param(cmd->params, positional_param_index,
                                     &param_info);
      if (rv) {
        fprintf(stderr, "Unexpected positional param at index %d\n",
                positional_param_index);
        return -1;
      }
      inv->args[param_info.index] = argv[i];
    }
  }
  return 0;
}

static int fill_global_flags(struct htool_invocation* inv,
                             const struct htool_cmd* cmd, int argc,
                             const char* const* argv) {
  inv->cmd = cmd;
  int num_params = 0;
  for (; cmd->params[num_params].type != HTOOL_PARAM_END; num_params++);
  inv->args = calloc(num_params, sizeof(const char*));
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] != '-') {
      // the first non-flag parameter
      return i;
    }
    struct param_info param_info;
    const char* value;
    int rv = find_flag(cmd->params, argv[i], &param_info, &value);
    if (rv) {
      fprintf(stderr, "Unknown flag %s\n", argv[i]);
      return -1;
    }
    if (param_info.param->type == HTOOL_FLAG_VALUE && !value) {
      if (i + 1 == argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for flag %s\n", argv[i]);
        return -1;
      }
      value = argv[i + 1];

      // Don't process the flag value
      i++;
    }
    inv->args[param_info.index] = value;
  }
  return argc;
}

static struct htool_invocation global_flags_inv = {};

struct htool_invocation* htool_global_flags(void) { return &global_flags_inv; }

int htool_main(const struct htool_param* global_flags,
               const struct htool_cmd* cmds, int argc,
               const char* const* argv) {
  static struct htool_cmd global_flags_cmd;
  global_flags_cmd = (struct htool_cmd){
      .params = global_flags,
  };
  int num_global_flag_args =
      fill_global_flags(&global_flags_inv, &global_flags_cmd, argc, argv);
  if (num_global_flag_args < 0) {
    return -1;
  }

  bool print_version;
  int rv =
      htool_get_param_bool(htool_global_flags(), "version", &print_version);
  if (rv) {
    return rv;
  }

  if (print_version) {
    printf("%s\n", STABLE_GIT_COMMIT);
    return 0;
  }

  argc -= num_global_flag_args;
  argv += num_global_flag_args;

  int num_verb_words;
  const struct htool_cmd* cmd = find_command(cmds, argc, argv, &num_verb_words);
  if (!cmd) {
    fprintf(stderr, "Unknown subcommand\n");
    enumerate_cmds(cmds);
    fprintf(stderr, "\nGlobal flags:\n");
    print_flags(global_flags);
    return -1;
  }
  argc -= num_verb_words;
  argv += num_verb_words;

  struct htool_invocation inv;
  rv = fill_cmd_invocation(&inv, cmd, argc, argv);
  if (rv != 0) {
    return rv;
  }
  if (cmd->deprecation_message != NULL) {
    fprintf(stderr, "[WARNING] %s\n", cmd->deprecation_message);
  }
  rv = cmd->func(&inv);
  free(inv.args);
  return rv;
}

int64_t parse_time_string_us(const char* time_str) {
    if (!time_str || *time_str == '\0') {
        return -1; // Invalid input
    }

    char* endptr;
    long long val = strtoll(time_str, &endptr, 10);

    if (endptr == time_str || val < 0) {
        return -1; // No digits found or negative value
    }

    // Skip whitespace
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) {
        endptr++;
    }

    uint64_t multiplier = 1000000; // Default to seconds if no unit

    if (*endptr != '\0') {
        // Check for units (case-insensitive)
        if (tolower((unsigned char)endptr[0]) == 's' && endptr[1] == '\0') {
            multiplier = 1000000; // seconds
        } else if (tolower((unsigned char)endptr[0]) == 'm' &&
                   tolower((unsigned char)endptr[1]) == 's' && endptr[2] == '\0') {
            multiplier = 1000; // milliseconds
        } else if (tolower((unsigned char)endptr[0]) == 'u' &&
                   tolower((unsigned char)endptr[1]) == 's' && endptr[2] == '\0') {
            multiplier = 1; // microseconds
        } else {
            return -1; // Invalid unit or extra characters
        }
    }

    // Check for potential overflow before multiplying
    if (val > INT64_MAX / multiplier) {
         return -1; // Overflow
    }

    return (int64_t)val * multiplier;
}
