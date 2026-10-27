// Copyright 2024 Google LLC
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

#include "transports/libhoth_dbus.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>

#include "transports/libhoth_device.h"

static libhoth_error dbus_err_posix(int errnum) {
  if (errnum == 0) {
    return HOTH_SUCCESS;
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_POSIX, errnum);
}

static libhoth_error dbus_err_libhoth(int libhoth_err) {
  if (libhoth_err == LIBHOTH_OK) {
    return HOTH_SUCCESS;
  }
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_INIT, HOTH_HOST_SPACE_LIBHOTH,
                               libhoth_err);
}

#define HOTHD_SERVICE "xyz.openbmc_project.Control.Hoth"
#define HOTHD_OBJECT "/xyz/openbmc_project/Control/Hoth"
#define HOTHD_INTERFACE "xyz.openbmc_project.Control.Hoth"
#define SEND_HOST_CMD_METHOD "SendHostCommand"

struct libhoth_dbus_device {
  // A handle to the system bus.
  sd_bus* bus;

  // A pending D-Bus host command request.
  sd_bus_message* request;

  char* service;

  char* object;
};

static libhoth_error send(struct libhoth_device* dev, const void* request,
                          size_t request_size) {
  struct libhoth_dbus_device* ctx = (struct libhoth_dbus_device*)dev->user_ctx;

  if (ctx->request) {
    // Clear the pending request because we can't have more than one.
    sd_bus_message_unref(ctx->request);
    ctx->request = NULL;
  }

  sd_bus_message* message = NULL;

  // Create a D-Bus message for our host command request.
  int rv = sd_bus_message_new_method_call(ctx->bus, &message, ctx->service,
                                          ctx->object, HOTHD_INTERFACE,
                                          SEND_HOST_CMD_METHOD);
  if (rv < 0) {
    fprintf(stderr, "Failed to create D-Bus message: %s\n", strerror(-rv));
    goto cleanup;
  }

  // Copy the host command request bytes into the D-Bus message.
  rv = sd_bus_message_append_array(message, 'y', request, request_size);
  if (rv < 0) {
    fprintf(stderr, "Failed to copy request bytes into D-Bus message: %s\n",
            strerror(-rv));
    goto cleanup;
  }

  // Record the pending request.
  ctx->request = message;
  return HOTH_SUCCESS;

cleanup:
  sd_bus_message_unref(message);
  return dbus_err_posix(-rv);
}

static libhoth_error receive(struct libhoth_device* dev, void* response,
                             size_t max_response_size, size_t* actual_size,
                             int timeout_ms) {
  struct libhoth_dbus_device* ctx = (struct libhoth_dbus_device*)dev->user_ctx;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message* reply = NULL;
  libhoth_error rc = HOTH_SUCCESS;

  if (!ctx->request) {
    fprintf(stderr,
            "Can't receive a response because there's no pending request.\n");
    rc = dbus_err_libhoth(LIBHOTH_ERR_FAIL);
    goto cleanup;
  }

  // Send the pending host command request.
  uint64_t timeout_usec = timeout_ms * 1000;
  int rv = sd_bus_call(ctx->bus, ctx->request, timeout_usec, &error, &reply);
  if (rv < 0) {
    fprintf(stderr, "D-Bus call failed: %s\n", error.message);
    rc = dbus_err_posix(-rv);
    goto cleanup;
  }

  // Read out host command response bytes.
  const void* buf = NULL;
  size_t size = 0;
  rv = sd_bus_message_read_array(reply, 'y', &buf, &size);
  if (rv < 0) {
    fprintf(stderr, "Failed to read response array: %s\n", strerror(-rv));
    rc = dbus_err_posix(-rv);
    goto cleanup;
  }

  if (size > max_response_size) {
    fprintf(stderr, "response size (%ld) greater than max allowed size (%ld)\n",
            size, max_response_size);
    rc = dbus_err_libhoth(LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW);
    goto cleanup;
  }

  if (actual_size) {
    *actual_size = size;
  }

  // `buf` is reference to a byte array inside of `reply`.
  // `reply` deallocates when this function ends.
  // We need to copy the response bytes out.
  memcpy(response, buf, size);

cleanup:
  sd_bus_message_unref(reply);
  sd_bus_error_free(&error);
  sd_bus_message_unref(ctx->request);
  ctx->request = NULL;
  return rc;
}

static libhoth_error close(struct libhoth_device* dev) {
  struct libhoth_dbus_device* ctx = (struct libhoth_dbus_device*)dev->user_ctx;

  free(ctx->object);
  ctx->object = NULL;

  free(ctx->service);
  ctx->service = NULL;

  sd_bus_message_unref(ctx->request);
  ctx->request = NULL;

  sd_bus_unref(ctx->bus);
  ctx->bus = NULL;

  free(ctx);
  dev->user_ctx = NULL;

  return HOTH_SUCCESS;
}

static libhoth_error claim(struct libhoth_device* dev) {
  // no-op
  return HOTH_SUCCESS;
}

static libhoth_error release(struct libhoth_device* dev) {
  // no-op
  return HOTH_SUCCESS;
}

static libhoth_error reconnect(struct libhoth_device* dev) {
  // no-op
  return HOTH_SUCCESS;
}

char* with_hoth_id(const char* base, char delimiter, const char* hoth_id) {
  size_t base_len = strlen(base);
  size_t hoth_id_len = strlen(hoth_id);

  // base + delimiter + hoth_id + NULL TERMINATOR
  char* ret = calloc(base_len + 1 + hoth_id_len + 1, sizeof(char));
  if (ret == NULL) {
    return NULL;
  }

  strcpy(ret, base);

  if (hoth_id_len == 0) {
    // Nothing to append.
    return ret;
  }

  // Append delimiter and hoth_id.
  ret[base_len] = delimiter;
  strcpy(ret + base_len + 1, hoth_id);
  return ret;
}

libhoth_error libhoth_dbus_open(
    const struct libhoth_dbus_device_init_options* options,
    struct libhoth_device** out) {
  *out = NULL;

  if (!options || !options->hoth_id || !out) {
    return dbus_err_libhoth(LIBHOTH_ERR_INVALID_PARAMETER);
  }

  sd_bus* bus = NULL;
  struct libhoth_device* dev = NULL;
  struct libhoth_dbus_device* dbus_dev = NULL;
  char* service = NULL;
  char* object = NULL;
  libhoth_error status = HOTH_SUCCESS;

  int rv = sd_bus_open_system(&bus);
  if (rv < 0) {
    fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-rv));
    status = dbus_err_posix(-rv);
    goto cleanup;
  }

  dev = calloc(1, sizeof(struct libhoth_device));
  if (dev == NULL) {
    status = dbus_err_libhoth(LIBHOTH_ERR_MALLOC_FAILED);
    goto cleanup;
  }

  dbus_dev = calloc(1, sizeof(struct libhoth_dbus_device));
  if (dbus_dev == NULL) {
    status = dbus_err_libhoth(LIBHOTH_ERR_MALLOC_FAILED);
    goto cleanup;
  }

  service = with_hoth_id(HOTHD_SERVICE, '.', options->hoth_id);
  if (service == NULL) {
    status = dbus_err_libhoth(LIBHOTH_ERR_MALLOC_FAILED);
    goto cleanup;
  }

  object = with_hoth_id(HOTHD_OBJECT, '/', options->hoth_id);
  if (object == NULL) {
    status = dbus_err_libhoth(LIBHOTH_ERR_MALLOC_FAILED);
    goto cleanup;
  }

  dbus_dev->bus = bus;
  dbus_dev->service = service;
  dbus_dev->object = object;

  dev->send = send;
  dev->receive = receive;
  dev->close = close;
  dev->claim = claim;
  dev->release = release;
  dev->reconnect = reconnect;
  dev->user_ctx = dbus_dev;

  *out = dev;
  return HOTH_SUCCESS;

cleanup:
  free(object);
  free(service);
  free(dbus_dev);
  free(dev);
  sd_bus_unref(bus);
  return status;
}
