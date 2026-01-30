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
    memcpy(request_param_value, request_params[i].data, request_params[i].size);
  }

  // May need to remove bytes_read and replace it with Null in
  // libhoth_hostcmd_exec
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

static int read_security_v2_serialized_header(
    struct security_v2_buffer* buffer,
    const struct security_v2_serialized_response_hdr** header) {
  const struct security_v2_serialized_response_hdr* response_header;

  if (!buffer || !header) {
    fprintf(stderr, "Arguments cannot be NULL");
    return -1;
  }

  // Read the response's header.
  int status =
      consume_bytes(buffer, sizeof(struct security_v2_serialized_response_hdr),
                    (uint8_t**)&response_header);
  if (status != 0 || !response_header) {
    fprintf(stderr, "Failed to initialize response, cannot read header.");
    return -1;
  }

  if (response_header->reserved != 0) {
    fprintf(stderr, "Reserved field non-zero.");
    return -1;
  }

  *header = response_header;

  return 0;
}

static int validate_param_padding(
    struct security_v2_buffer* buffer,
    const struct security_v2_serialized_param* param) {
  const uint8_t* padding;
  size_t param_padding_size = padding_size(param->size);
  int i;

  if (param_padding_size == 0) {
    // No padding check necessary.
    return 0;
  }

  // If the parameter value's length requires padding, we need
  // to read the padding bytes and ensure they are all zero.
  int status = consume_bytes(buffer, param_padding_size, (uint8_t**)&padding);

  if (status != 0 || !padding) {
    fprintf(stderr,
            "Failed to validate param padding, could not read padding data.\n");
    return -1;
  }

  for (i = 0; i < param_padding_size; ++i) {
    if (padding[i] != 0) {
      fprintf(stderr,
              "Failed to validate param padding, padding is non-zero.\n");
      return -1;
    }
  }

  return 0;
}

static int read_security_v2_serialized_params(
    struct security_v2_buffer* buffer,
    const struct security_v2_serialized_param** param) {
  const uint8_t* value;
  if (!buffer || !param) {
    fprintf(stderr,
            "Failed to read response param, arguments cannot be NULL.\n");
    return -1;
  }

  // Read the parameter's header.
  int status = consume_bytes(buffer, sizeof(**param), (uint8_t**)param);
  if (status != 0 || !*param) {
    fprintf(stderr, "Failed to read response param header.\n");
    return -1;
  }

  if ((*param)->reserved != 0) {
    fprintf(stderr, "Reserved field non-zero.\n");
    return -1;
  }

  // Read the parameter's value.
  status = consume_bytes(buffer, (*param)->size, (uint8_t**)&value);
  if (status != 0 || !value) {
    fprintf(stderr, "Failed to read response param data.\n");
    return -1;
  }

  status = validate_param_padding(buffer, *param);
  if (status != 0) {
    return status;
  }

  return 0;
}

int htool_exec_security_v2_serialized_cmd(
    struct libhoth_device* dev, uint8_t major, uint8_t minor,
    uint16_t base_command, struct security_v2_buffer* request_buffer,
    const struct security_v2_param* request_params,
    uint16_t request_param_count, struct security_v2_buffer* response_buffer,
    const struct security_v2_serialized_param** response_params[],
    uint16_t response_param_count) {
  int status = 0;
  const struct security_v2_serialized_response_hdr* response_hdr;
  status = htool_exec_security_v2_cmd(
      dev, major, minor, base_command, request_buffer, request_params,
      request_param_count, response_buffer, /*response_params=*/NULL,
      /*response_param_count=*/0);
  if (status != 0) {
    return -1;
  }

  status = read_security_v2_serialized_header(response_buffer, &response_hdr);
  if (status != 0) {
    return -1;
  }

  if (response_hdr->param_count != response_param_count) {
    fprintf(stderr, "Expected a %u response params, Got %u\n",
            response_param_count, response_hdr->param_count);
    return -1;
  }

  for (int i = 0; i < response_param_count; ++i) {
    status =
        read_security_v2_serialized_params(response_buffer, response_params[i]);
    if (status != 0) {
      return status;
    }
  }
  return status;
}

int copy_param(const struct security_v2_serialized_param* param, void* output,
               size_t output_size) {
  if (param->size != output_size) {
    fprintf(stderr,
            "Parameter is too large (%u bytes) to fit in "
            "the output buffer (%lu bytes)\n",
            param->size, output_size);
    return -1;
  }

  memcpy(output, param->value, output_size);
  return 0;
}
