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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
// for MIN()
#include <sys/param.h>

#include "../libhoth.h"
#include "host_commands.h"
#include "htool.h"
#include "htool_progress.h"
#include "htool_spi_proxy.h"
#include "htool_usb.h"

const uint8_t SPI_OP_PAGE_PROGRAM = 0x02;
const uint8_t SPI_OP_READ = 0x03;
const uint8_t SPI_OP_ERASE_4K = 0x20;
const uint8_t SPI_OP_ERASE_64K = 0xd8;
const uint8_t SPI_OP_WRITE_ENABLE = 0x06;
const uint8_t SPI_OP_ENTER_4B = 0xb7;

struct spi_operation_transaction {
  size_t header_offset;
  size_t skip_miso_nbytes;
  uint8_t* miso_dest_buf;
  size_t miso_dest_buf_len;
};

#define MAX_TRANSACTIONS 12
#define MAX_SPI_OP_PAYLOAD_BYTES 1016
#define OPCODE_AND_ADDRESS_MAX_SIZE 5
#define READ_CHUNK_SIZE                                                 \
  (MAX_SPI_OP_PAYLOAD_BYTES - sizeof(struct ec_spi_operation_request) - \
   OPCODE_AND_ADDRESS_MAX_SIZE)

struct spi_operation {
  uint8_t buf[MAX_SPI_OP_PAYLOAD_BYTES];
  size_t pos;

  struct spi_operation_transaction transactions[MAX_TRANSACTIONS];
  size_t num_transactions;
};

static void spi_operation_init(struct spi_operation* op) {
  op->pos = 0;
  op->num_transactions = 0;
}

static int spi_operation_execute(struct spi_operation* op,
                                 struct libhoth_device* dev) {
  uint8_t response_buf[MAX_SPI_OP_PAYLOAD_BYTES];
  size_t response_len;

  // hexdump(op->buf, op->pos);
  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SPI_OPERATION,
      /*version=*/0, op->buf, op->pos, response_buf, sizeof(response_buf),
      &response_len);
  if (status != 0) {
    return status;
  }
  size_t pos = 0;
  for (size_t i = 0; i < op->num_transactions; i++) {
    struct spi_operation_transaction* transaction = &op->transactions[i];
    if (transaction->miso_dest_buf) {
      if (transaction->miso_dest_buf_len > 0) {
        if (pos + transaction->miso_dest_buf_len > response_len) {
          fprintf(stderr,
                  "returned SPI operation payload is smaller than expected");
          return -1;
        }
        memcpy(transaction->miso_dest_buf,
               &response_buf[pos + transaction->skip_miso_nbytes],
               transaction->miso_dest_buf_len);
      }
    }
    pos += transaction->skip_miso_nbytes + transaction->miso_dest_buf_len;
  }
  return 0;
}

static void spi_operation_begin_transaction(struct spi_operation* op) {
  assert(op->num_transactions < MAX_TRANSACTIONS);
  assert(op->pos + sizeof(struct ec_spi_operation_request) < sizeof(op->buf));

  op->transactions[op->num_transactions] = (struct spi_operation_transaction){
      .header_offset = op->pos,
  };
  op->pos += sizeof(struct ec_spi_operation_request);
}

static void spi_operation_write_mosi(struct spi_operation* op, const void* mosi,
                                     size_t mosi_len) {
  assert(op->pos + mosi_len < sizeof(op->buf));
  memcpy(&op->buf[op->pos], mosi, mosi_len);
  op->pos += mosi_len;
}

static void spi_operation_write_mosi_address(struct spi_operation* op,
                                             bool is_4_byte, uint32_t addr) {
  const uint8_t buf[4] = {
      (addr >> 24) & 0xff,
      (addr >> 16) & 0xff,
      (addr >> 8) & 0xff,
      (addr >> 0) & 0xff,
  };
  spi_operation_write_mosi(op, (is_4_byte ? &buf[0] : &buf[1]),
                           (is_4_byte ? 4 : 3));
}

static void spi_operation_read_miso_and_end_transaction(
    struct spi_operation* op, void* miso_dest_buf, size_t miso_dest_buf_len) {
  assert(op->num_transactions < MAX_TRANSACTIONS);

  struct spi_operation_transaction* transaction =
      &op->transactions[op->num_transactions];

  // The number of bytes provided to write to MOSI at the beginning
  // of the transaction
  size_t mosi_len = op->pos - transaction->header_offset -
                    sizeof(struct ec_spi_operation_request);

  transaction->skip_miso_nbytes = mosi_len;
  transaction->miso_dest_buf = miso_dest_buf;
  transaction->miso_dest_buf_len = miso_dest_buf_len;

  struct ec_spi_operation_request req = {
      .mosi_len = mosi_len,
      .miso_len = miso_dest_buf_len > 0 ? (mosi_len + miso_dest_buf_len) : 0,
  };
  memcpy(&op->buf[transaction->header_offset], &req, sizeof(req));

  op->num_transactions++;
}

static void spi_operation_end_transaction(struct spi_operation* op) {
  spi_operation_read_miso_and_end_transaction(op, NULL, 0);
}

static int spi_read_chunk(const struct htool_spi_proxy* spi, uint32_t addr, void* buf,
                          size_t len) {
  struct spi_operation op;
  spi_operation_init(&op);

  spi_operation_begin_transaction(&op);
  spi_operation_write_mosi(&op, &SPI_OP_READ, sizeof(SPI_OP_READ));
  spi_operation_write_mosi_address(&op, spi->is_4_byte, addr);
  spi_operation_read_miso_and_end_transaction(&op, buf, len);

  return spi_operation_execute(&op, spi->dev);
}

int htool_spi_proxy_read(const struct htool_spi_proxy* spi, uint32_t addr, void* buf,
                   size_t len) {
  uint8_t* cbuf = (uint8_t*)buf;
  while (len > 0) {
    size_t read_len = MIN(len, READ_CHUNK_SIZE);
    int status = spi_read_chunk(spi, addr, cbuf, read_len);
    if (status) {
      return status;
    }
    len -= read_len;
    addr += read_len;
    cbuf += read_len;
  }
  return 0;
}

int htool_spi_proxy_verify(const struct htool_spi_proxy* spi, uint32_t addr,
                     const void* buf, size_t len,
                     const struct htool_progress* progress) {
  uint8_t read_buf[READ_CHUNK_SIZE];
  const uint8_t* cbuf = (const uint8_t*)buf;
  size_t len_remaining = len;

  uint32_t last_progress_addr = addr;
  while (len_remaining > 0) {
    size_t read_len = MIN(len_remaining, sizeof(read_buf));
    int status = spi_read_chunk(spi, addr, read_buf, read_len);
    if (status) {
      return status;
    }
    for (size_t i = 0; i < read_len; i++) {
      if (cbuf[i] != read_buf[i]) {
        fprintf(stderr,
                "Verification failed at address 0x%08lx: expected 0x%02x but "
                "was 0x%02x\n",
                (unsigned long)(addr + i), cbuf[i], read_buf[i]);
        return -1;
      }
    }
    len_remaining -= read_len;
    addr += read_len;
    cbuf += read_len;

    if (progress &&
        (len_remaining == 0 || addr >= last_progress_addr + 65536)) {
      last_progress_addr = addr;
      progress->func(progress->param, len - len_remaining, len);
    }
  }
  return 0;
}

static void spi_write_page(struct spi_operation* op,
                           const struct htool_spi_proxy* spi, uint32_t addr,
                           const uint8_t* buf, size_t len) {
  spi_operation_begin_transaction(op);
  spi_operation_write_mosi(op, &SPI_OP_WRITE_ENABLE,
                           sizeof(SPI_OP_WRITE_ENABLE));
  spi_operation_end_transaction(op);

  spi_operation_begin_transaction(op);
  spi_operation_write_mosi(op, &SPI_OP_PAGE_PROGRAM,
                           sizeof(SPI_OP_PAGE_PROGRAM));
  spi_operation_write_mosi_address(op, spi->is_4_byte, addr);
  spi_operation_write_mosi(op, buf, len);
  spi_operation_end_transaction(op);

  // NOTE: Waiting for the busy bit to clear is not necessary when using
  // SPI_OPERATION host commands
}

static void spi_erase_generic(struct spi_operation* op,
                              const struct htool_spi_proxy* spi, uint32_t addr,
                              uint8_t opcode) {
  spi_operation_begin_transaction(op);
  spi_operation_write_mosi(op, &SPI_OP_WRITE_ENABLE,
                           sizeof(SPI_OP_WRITE_ENABLE));
  spi_operation_end_transaction(op);

  spi_operation_begin_transaction(op);
  spi_operation_write_mosi(op, &opcode, sizeof(opcode));
  spi_operation_write_mosi_address(op, spi->is_4_byte, addr);
  spi_operation_end_transaction(op);

  // NOTE: Waiting for the busy bit to clear is not necessary when using
  // SPI_OPERATION host commands
}

int htool_spi_proxy_init(struct htool_spi_proxy* spi, struct libhoth_device* dev) {
  spi->dev = dev;
  spi->is_4_byte = true;

  struct spi_operation op;
  spi_operation_init(&op);
  spi_operation_begin_transaction(&op);
  spi_operation_write_mosi(&op, &SPI_OP_ENTER_4B, sizeof(SPI_OP_ENTER_4B));
  spi_operation_end_transaction(&op);

  int status = spi_operation_execute(&op, spi->dev);
  if (status == HTOOL_ERROR_HOST_COMMAND_START + EC_RES_BUS_ERROR) {
    fprintf(
        stderr,
        "This is likely because the target device is not in reset, and thus it "
        "is not safe to use the SPI bus through a non-SPI transport. Try using "
        "'htool target reset on' to put the target in reset first.\n");
  }
  return status;
}

int htool_spi_proxy_update(const struct htool_spi_proxy* spi, uint32_t addr,
                     const void* buf, size_t len,
                     const struct htool_progress* progress) {
  const uint32_t SPI_PAGE_SIZE = 256;

  // There is only enough space in the buffer for 3 page writes (and associated
  // erases and write-enable transactions)
  const uint32_t MAX_PAGES_PER_OP = 3;

  struct spi_operation op;
  spi_operation_init(&op);

  uint8_t* cbuf = (uint8_t*)buf;
  size_t pages_in_op = 0;

  uint32_t need_erase_addr = addr;

  uint32_t last_progress_addr = addr;

  size_t len_remaining = len;
  while (len_remaining > 0) {
    size_t page_end = ((addr + SPI_PAGE_SIZE) / SPI_PAGE_SIZE) * SPI_PAGE_SIZE;

    if (page_end > need_erase_addr) {
      uint32_t erase_start_64k = (addr / 65536) * 65536;
      uint32_t erase_start_4k = (addr / 4096) * 4096;
      uint32_t erase_end_64k = erase_start_64k + 65536;
      uint32_t erase_end_4k = erase_start_4k + 4096;

      if ((erase_start_64k >= addr || erase_start_64k == erase_start_4k) &&
          (erase_end_64k <= (addr + len_remaining) ||
           erase_end_64k == erase_end_4k)) {
        need_erase_addr = erase_end_64k;
        spi_erase_generic(&op, spi, erase_start_64k, SPI_OP_ERASE_64K);
      } else {
        need_erase_addr = erase_end_4k;
        spi_erase_generic(&op, spi, erase_start_4k, SPI_OP_ERASE_4K);
      }
    }
    size_t write_len = MIN(page_end - addr, len_remaining);
    spi_write_page(&op, spi, addr, cbuf, write_len);
    len_remaining -= write_len;
    addr += write_len;
    cbuf += write_len;

    pages_in_op++;

    if (pages_in_op >= MAX_PAGES_PER_OP || len_remaining == 0) {
      pages_in_op = 0;

      int status = spi_operation_execute(&op, spi->dev);
      if (status) {
        return status;
      }
      if (progress &&
          (len_remaining == 0 || addr >= last_progress_addr + 65536)) {
        last_progress_addr = addr;
        progress->func(progress->param, len - len_remaining, len);
      }
      spi_operation_init(&op);
    }
  }
  return 0;
}
