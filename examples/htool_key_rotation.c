// Copyright 2025 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.guage governing permissions and
// limitations under the License.

#include "htool_key_rotation.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/key_rotation.h"

static const char* get_validation_method_string(uint32_t validation_method) {
  switch (validation_method) {
    case 1:
      return "Embedded Key";
    case 2:
      return "Payload Key";
    case 3:
      return "Hash";
    default:
      return "Unknown";
  }
}

int htool_key_rotation_get_status(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_status status;
  enum key_rotation_err ret = libhoth_key_rotation_get_status(dev, &status);
  if (ret) {
    fprintf(stderr, "Failed to get key rotation status\n");
    return -1;
  }

  printf("version        : %u\n", status.version);
  printf("image_family   : %u\n", status.image_family);
  printf("image_family_variant   : %u\n", status.image_family_variant);
  printf("validation_method   : %s\n",
         get_validation_method_string(status.validation_method));
  printf("validation_key_data   : 0x%x\n", status.validation_key_data);
  printf("validation_hash_data   : 0x%x\n", status.validation_hash_data);
  return 0;
}

int htool_key_rotation_get_version(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_record_version version;
  enum key_rotation_err ret = libhoth_key_rotation_get_version(dev, &version);
  if (ret) {
    fprintf(stderr, "Failed to get key rotation version\n");
    return -1;
  }
  printf("version        : %u\n", version.version);
  return 0;
}

static int read_image_file(const char* image_file, uint8_t** image,
                           size_t* size) {
  int fd = -1;
  int result = 0;
  struct stat statbuf;

  fd = open(image_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", image_file, strerror(errno));
    return -1;
  }

  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    result = -1;
    goto cleanup;
  }

  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "file too large\n");
    result = -1;
    goto cleanup;
  }

  *size = statbuf.st_size;
  *image = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (*image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    result = -1;
    goto cleanup;
  }

cleanup:
  if (fd != -1) {
    if (close(fd) != 0) {
      fprintf(stderr, "close error: %s\n", strerror(errno));
      if (result == 0) {
        result = -1;
      }
    }
  }
  if (result != 0 && *image != MAP_FAILED && *size > 0) {
    if (munmap(*image, *size) != 0) {
      fprintf(stderr, "munmap error: %s\n", strerror(errno));
    }
  }
  return result;
}

int htool_key_rotation_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  const char* image_file;
  if (htool_get_param_string(inv, "source-file", &image_file) != 0) {
    return -1;
  }

  uint8_t* image = MAP_FAILED;
  size_t size = 0;
  int result = read_image_file(image_file, &image, &size);
  if (result != 0) {
    return result;
  }

  enum key_rotation_err key_ret = libhoth_key_rotation_update(dev, image, size);
  if (key_ret) {
    fprintf(stderr, "Failed to update key rotation record\n");
    result = key_ret;
  }

  if (image != MAP_FAILED) {
    if (munmap(image, size) != 0) {
      fprintf(stderr, "munmap error: %s\n", strerror(errno));
      result = -1;
    }
  }
  return result;
}

int htool_key_rotation_payload_status(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_payload_status payload_status;
  enum key_rotation_err ret =
      libhoth_key_rotation_payload_status(dev, &payload_status);
  if (ret) {
    fprintf(stderr, "Failed to get key rotation payload status\n");
    return -1;
  }
  printf("validation_method   : %s\n",
         get_validation_method_string(payload_status.validation_method));
  printf("validation_key_data   : 0x%x\n", payload_status.validation_key_data);
  printf("validation_hash_data   : 0x%x\n",
         payload_status.validation_hash_data);
  return 0;
}

static int get_key_rotation_read_half(const char* read_half,
                                      uint32_t* read_half_value) {
  if (!strcmp(read_half, "active")) {
    *read_half_value = KEY_ROTATION_RECORD_READ_HALF_ACTIVE;
  } else if (!strcmp(read_half, "staging")) {
    *read_half_value = KEY_ROTATION_RECORD_READ_HALF_STAGING;
  } else if (!strcmp(read_half, "a")) {
    *read_half_value = KEY_ROTATION_RECORD_READ_HALF_A;
  } else if (!strcmp(read_half, "b")) {
    *read_half_value = KEY_ROTATION_RECORD_READ_HALF_B;
  } else {
    fprintf(stderr, "Invalid read_half value: %s\n", read_half);
    return -1;
  }
  return 0;
}

int htool_key_rotation_read(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  uint32_t offset = 0;
  uint32_t size = 0;
  const char* read_half_string;
  if (htool_get_param_u32(inv, "offset", &offset) ||
      htool_get_param_u32(inv, "size", &size) ||
      htool_get_param_string(inv, "half", &read_half_string)) {
    return -1;
  }
  uint32_t read_half = 0;
  int ret_half = get_key_rotation_read_half(read_half_string, &read_half);
  if (ret_half) {
    return -1;
  }
  const char* output_file = NULL;
  bool output_to_file =
      (htool_get_param_string(inv, "output_file", &output_file) == 0) &&
      (output_file != NULL) && (strlen(output_file) > 0);
  int fd = -1;
  if (output_to_file) {
    if (access(output_file, F_OK) == 0) {
      fprintf(stderr,
              "Warning: File '%s' exists and will be overwritten. Continue? "
              "(y/N) ",
              output_file);
      char confirmation;
      if (scanf(" %c", &confirmation) != 1 ||
          (confirmation != 'y' && confirmation != 'Y')) {
        fprintf(stderr, "Operation cancelled.\n");
        return -1;
      }
    }
    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
      fprintf(stderr, "Error opening file %s: %s\n", output_file,
              strerror(errno));
      return -1;
    }
  }

  struct hoth_response_key_rotation_record_read read_response;
  enum key_rotation_err ret_read =
      libhoth_key_rotation_read(dev, offset, size, read_half, &read_response);
  if (ret_read) {
    fprintf(stderr, "Failed to read key rotation record\n");
    if (fd != -1) {
      close(fd);
    }
    return -1;
  }
  if (output_to_file) {
    if (write(fd, read_response.data, size) != size) {
      fprintf(stderr, "Error writing to file %s: %s\n", output_file,
              strerror(errno));
      close(fd);
      return -1;
    }
    if (close(fd) != 0) {
      fprintf(stderr, "close error: %s\n", strerror(errno));
      return -1;
    }
  } else {
    printf("Key rotation record data:\n");
    for (int i = 0; i < size; i++) {
      printf("0x%02X ", read_response.data[i]);
      if ((i + 1) % 16 == 0) {
        printf("\n");
      }
    }
    printf("\n");
  }
  return 0;
}

static int get_key_rotation_chunk_type(const char* chunk_type_string,
                                       uint32_t* chunk_typecode) {
  if (!strcmp(chunk_type_string, "pkey")) {
    *chunk_typecode = KEY_ROTATION_CHUNK_TYPE_CODE_PKEY;
  } else if (!strcmp(chunk_type_string, "hash")) {
    *chunk_typecode = KEY_ROTATION_CHUNK_TYPE_CODE_HASH;
  } else if (!strcmp(chunk_type_string, "bkey")) {
    *chunk_typecode = KEY_ROTATION_CHUNK_TYPE_CODE_BKEY;
  } else if (!strcmp(chunk_type_string, "bash")) {
    *chunk_typecode = KEY_ROTATION_CHUNK_TYPE_CODE_BASH;
  } else {
    fprintf(stderr, "Invalid chunk_type value: %s\n", chunk_type_string);
    return -1;
  }
  return 0;
}

int htool_key_rotation_read_chunk_type(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  uint32_t offset = 0;
  uint32_t size = 0;
  uint32_t chunk_index = 0;
  const char* chunk_type_string;
  if (htool_get_param_u32(inv, "offset", &offset) ||
      htool_get_param_u32(inv, "size", &size) ||
      htool_get_param_string(inv, "type", &chunk_type_string) ||
      htool_get_param_u32(inv, "idx", &chunk_index)) {
    return -1;
  }
  uint32_t chunk_typecode = 0;
  int ret_half =
      get_key_rotation_chunk_type(chunk_type_string, &chunk_typecode);
  if (ret_half) {
    return -1;
  }
  const char* output_file = NULL;
  bool output_to_file =
      (htool_get_param_string(inv, "output_file", &output_file) == 0) &&
      (output_file != NULL) && (strlen(output_file) > 0);
  int fd = -1;
  if (output_to_file) {
    if (access(output_file, F_OK) == 0) {
      fprintf(stderr,
              "Warning: File '%s' exists and will be overwritten. Continue? "
              "(y/N) ",
              output_file);
      char confirmation;
      if (scanf(" %c", &confirmation) != 1 ||
          (confirmation != 'y' && confirmation != 'Y')) {
        fprintf(stderr, "Operation cancelled.\n");
        return -1;
      }
    }
    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
      fprintf(stderr, "Error opening file %s: %s\n", output_file,
              strerror(errno));
      return -1;
    }
  }
  uint16_t response_size = 0;
  struct hoth_response_key_rotation_record_read read_response;
  enum key_rotation_err ret_read = libhoth_key_rotation_read_chunk_type(
      dev, chunk_typecode, chunk_index, offset, size, &read_response,
      &response_size);
  if (ret_read) {
    fprintf(stderr, "Failed to read chunk from key rotation record\n");
    return -1;
  }
  if (size == 0) {
    size = response_size;
  }
  if (size != response_size) {
    fprintf(
        stderr,
        "Error reading chunk from key rotation record. Expected %u; Got %u\n",
        size, response_size);
    return -1;
  }
  if (output_to_file) {
    if (write(fd, read_response.data, size) != size) {
      fprintf(stderr, "Error writing to file %s: %s\n", output_file,
              strerror(errno));
      close(fd);
      return -1;
    }
    if (close(fd) != 0) {
      fprintf(stderr, "close error: %s\n", strerror(errno));
      return -1;
    }
  } else {
    printf("Key rotation record data:\n");
    for (int i = 0; i < size; i++) {
      printf("0x%02X ", read_response.data[i]);
      if ((i + 1) % 16 == 0) {
        printf("\n");
      }
    }
    printf("\n");
  }
  return 0;
}

int htool_key_rotation_chunk_type_count(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  const char* chunk_type_string;
  if (htool_get_param_string(inv, "type", &chunk_type_string)) {
    return -1;
  }
  uint32_t chunk_typecode = 0;
  int ret_half =
      get_key_rotation_chunk_type(chunk_type_string, &chunk_typecode);
  if (ret_half) {
    return -1;
  }
  uint16_t chunk_count = 0;
  enum key_rotation_err ret_count =
      libhoth_key_rotation_chunk_type_count(dev, chunk_typecode, &chunk_count);
  if (ret_count) {
    fprintf(stderr, "Failed to get chunk type count\n");
    return -1;
  }
  printf("chunk_count: %u\n", chunk_count);
  return 0;
}

int htool_key_rotation_erase_record(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  enum key_rotation_err ret = libhoth_key_rotation_erase_record(dev);
  if (ret) {
    fprintf(stderr, "Failed to erase key rotation record\n");
    return -1;
  }
  printf("Key rotation record erased successfully\n");
  return 0;
}

int htool_key_rotation_set_mauv(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  uint32_t mauv;
  if (htool_get_param_u32(inv, "mauv", &mauv)) {
    return -1;
  }
  enum key_rotation_err ret = libhoth_key_rotation_set_mauv(dev, mauv);
  if (ret) {
    fprintf(stderr, "Failed to set key rotation MAUV\n");
    return -1;
  }
  printf("Key rotation MAUV set successfully\n");
  return 0;
}

int htool_key_rotation_get_mauv(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_mauv mauv;
  enum key_rotation_err ret = libhoth_key_rotation_get_mauv(dev, &mauv);
  if (ret) {
    fprintf(stderr, "Failed to get key rotation MAUV\n");
    return -1;
  }
  printf("Key rotation MAUV: %u\n", mauv.mauv);
  return 0;
}
