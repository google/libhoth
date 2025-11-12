#include "htool_security_v2.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

// Marks `bytes` as consumed in `buffer` and sets `output` to the start of
// the allocated region.
static int consume_bytes(struct security_v2_buffer* buffer, uint16_t bytes,
                         uint8_t** output) {
  if (buffer->bytes_consumed > buffer->size ||
      buffer->size - buffer->bytes_consumed < bytes) {
    return -1;
  }

  *output = buffer->data + buffer->bytes_consumed;
  buffer->bytes_consumed += bytes;
  return 0;
}



int htool_exec_security_v2_cmd(struct libhoth_device* dev, uint8_t major,
                               uint8_t minor, uint16_t base_command,
                               struct security_v2_buffer* request_buffer,
                               const struct security_v2_param* request_params,
                               uint16_t request_param_count,
                               struct security_v2_buffer* response_buffer,
                               struct security_v2_param* response_params,
                               uint16_t response_param_count) {
  struct hoth_security_v2_request_header* request_header;
  int status = consume_bytes(request_buffer, sizeof(*request_header),
                             (uint8_t**)&request_header);
  if (status != 0) {
    fprintf(stderr, "insufficient bytes for request header\n");
    return status;
  }
  request_header->major_command = major;
  request_header->minor_command = minor;
  request_header->param_count = request_param_count;

  for (int i = 0; i < request_param_count; ++i) {
    struct hoth_security_v2_parameter* request_param;
    status = consume_bytes(request_buffer, sizeof(*request_param),
                           (uint8_t**)&request_param);
    if (status != 0) {
      fprintf(stderr, "insufficient bytes for request param %d\n", i);
      return status;
    }
    request_param->size = request_params[i].size;

    uint8_t* request_param_value;
    status = consume_bytes(
        request_buffer,
        request_params[i].size + padding_size(request_params[i].size),
        &request_param_value);
    if (status != 0) {
      fprintf(stderr, "insufficient bytes for request param %d\n", i);
      return status;
    }
    memcpy(request_param_value, request_params[i].data,
           request_params[i].size);
  }

  // May need to remove bytes_read and replace it with Null in libhoth_hostcmd_exec
  size_t bytes_read;
  status = libhoth_hostcmd_exec(dev, base_command, 0, request_buffer->data,
                                request_buffer->size, response_buffer->data,
                                response_buffer->size, &bytes_read);
  if (status != 0) {
    // htool_exec_hostcmd logs to stderr, don't repeat here.
    return status;
  }
  response_buffer->size = (uint16_t)bytes_read;

  // Return 0 as there are no other actions needed under this case.
  if (response_param_count == 0) {
    return 0;
  }

  struct hoth_security_v2_response_header* response_header;
  status = consume_bytes(response_buffer, sizeof(*response_header),
                         (uint8_t**)&response_header);
  if (status != 0) {
    fprintf(stderr, "insufficient bytes for response header\n");
    return status;
  }
  if (response_header->param_count != response_param_count) {
    fprintf(stderr,
            "response_header->param_count (%d) != response_param_count (%d)\n",
            response_header->param_count, response_param_count);
    return -1;
  }

  // We're intentionally lax here and not checking for 0s in reserved
  // fields/padding.
  for (int i = 0; i < response_param_count; ++i) {
    struct hoth_security_v2_parameter* response_param;
    status = consume_bytes(response_buffer, sizeof(*response_param),
                           (uint8_t**)&response_param);
    if (status != 0) {
      fprintf(stderr, "insufficient bytes for response param %d\n", i);
      return status;
    }
    if (response_param->size != response_params[i].size) {
      fprintf(stderr,
              "response_param->size (%d) != response_params[%d]->size (%d)\n",
              response_param->size, i, response_params[i].size);
      return -1;
    }

    uint8_t* response_param_value;
    status = consume_bytes(
        response_buffer,
        response_params[i].size + padding_size(response_params[i].size),
        &response_param_value);
    if (status != 0) {
      fprintf(stderr, "insufficient bytes for response param %d\n", i);
      return status;
    }
    memcpy(response_params[i].data, response_param_value,
           response_params[i].size);
  }

  return 0;
}
