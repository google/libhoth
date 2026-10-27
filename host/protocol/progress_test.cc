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

#include "progress.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

namespace {

using ::testing::HasSubstr;

static struct timespec mock_time;

extern "C" struct timespec libhoth_progress_get_time(void) { return mock_time; }

class ProgressTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_time.tv_sec = 0;
    mock_time.tv_nsec = 0;
    libhoth_progress_stderr_init(&progress_, "Test Action");
    // Force TTY to true so we can test the output even if running in
    // non-interactive mode.
    progress_.is_tty = true;
  }

  struct libhoth_progress_stderr progress_;
};

TEST_F(ProgressTest, Init) {
  EXPECT_EQ(progress_.last_reported_val, 0);
  EXPECT_EQ(progress_.action_title, "Test Action");
  EXPECT_TRUE(progress_.is_tty);
  EXPECT_NE(progress_.progress.func, nullptr);
  EXPECT_EQ(progress_.progress.param, &progress_);
}

TEST_F(ProgressTest, StartAlwaysPrints) {
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 0, 100);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr("Test Action:   0%"));
  EXPECT_THAT(output, HasSubstr("0KiB / 0KiB"));
}

TEST_F(ProgressTest, EndAlwaysPrints) {
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 100, 100);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr("Test Action: 100%"));
  EXPECT_THAT(output, HasSubstr("0KiB / 0KiB"));
  // Should end with newline at 100%
  EXPECT_THAT(output, HasSubstr("\n"));
}

TEST_F(ProgressTest, UpdatesThrottled) {
  // First call (0%)
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 0, 1000);
  std::string output = testing::internal::GetCapturedStderr();
  EXPECT_THAT(output, HasSubstr("0%"));

  // Small update (< 1%) -> Should NOT print
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 5, 1000);  // 0.5%
  output = testing::internal::GetCapturedStderr();
  EXPECT_TRUE(output.empty());

  // Threshold update (== 1%) -> Should print
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 10, 1000);  // 1.0%
  output = testing::internal::GetCapturedStderr();
  EXPECT_THAT(output, HasSubstr("1%"));

  // Large update (>= 1%) -> Should print
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 20, 1000);  // 2.0%
  output = testing::internal::GetCapturedStderr();
  EXPECT_THAT(output, HasSubstr("2%"));
}

TEST_F(ProgressTest, ThroughputCalculation) {
  // 1 second passed
  mock_time.tv_sec = 1;
  mock_time.tv_nsec = 0;

  testing::internal::CaptureStderr();
  // 50 KiB transferred in 1 second
  progress_.progress.func(progress_.progress.param, 50 * 1024, 100 * 1024);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr("50KiB"));
  EXPECT_THAT(output, HasSubstr("50 KiB/sec"));
  // 50 KiB remaining at 50 KiB/s -> 1 second remaining
  EXPECT_THAT(output, HasSubstr(" 1 s remaining"));
}

TEST_F(ProgressTest, ThroughputCalculationSlow) {
  // 10 seconds passed
  mock_time.tv_sec = 10;
  mock_time.tv_nsec = 0;

  testing::internal::CaptureStderr();
  // 10 KiB transferred in 10 seconds = 1 KiB/s
  progress_.progress.func(progress_.progress.param, 10 * 1024, 110 * 1024);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr(" 1 KiB/sec"));
  // 100 KiB remaining at 1 KiB/s -> 100 seconds remaining
  EXPECT_THAT(output, HasSubstr(" 100 s remaining"));
}

TEST_F(ProgressTest, ThroughputCalculationFast) {
  // 0.5 seconds passed
  mock_time.tv_sec = 0;
  mock_time.tv_nsec = 500000000;

  testing::internal::CaptureStderr();
  // 1024 KiB transferred in 0.5 seconds = 2048 KiB/s
  progress_.progress.func(progress_.progress.param, 1024 * 1024, 2048 * 1024);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr(" 2048 KiB/sec"));
  // 1024 KiB remaining at 2048 KiB/s -> 0.5 seconds remaining
  EXPECT_THAT(output, HasSubstr(" 0 s remaining") /* 0.5 rounded down */);
}

TEST_F(ProgressTest, ZeroTotal) {
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 0, 0);
  std::string output = testing::internal::GetCapturedStderr();

  // 0/0 is treated as 100% in the code
  EXPECT_THAT(output, HasSubstr("100%"));
  EXPECT_THAT(output, HasSubstr("\n"));
}

TEST_F(ProgressTest, ZeroDuration) {
  // Explicitly set time to match start time (0,0) to force 0 duration
  mock_time.tv_sec = 0;
  mock_time.tv_nsec = 0;
  progress_.start_time = mock_time;

  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 50, 100);
  std::string output = testing::internal::GetCapturedStderr();

  // Should not crash and should use 1ms fallback
  EXPECT_THAT(output, HasSubstr("50%"));
  EXPECT_THAT(output, HasSubstr("KiB/sec"));
}

TEST_F(ProgressTest, SmallTotalThreshold) {
  testing::internal::CaptureStderr();
  // total < 100, threshold should be 1 byte
  progress_.progress.func(progress_.progress.param, 1, 50);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr("2%"));

  // Calling again with same value should NOT print (threshold check)
  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 1, 50);
  output = testing::internal::GetCapturedStderr();

  EXPECT_TRUE(output.empty());
}

TEST_F(ProgressTest, VeryLargeTransfer) {
  // 8 GiB total
  uint64_t total = 8ULL * 1024 * 1024 * 1024;
  uint64_t current = 4ULL * 1024 * 1024 * 1024;

  mock_time.tv_sec = 10;  // 10 seconds for 4GiB = 400MiB/s approx

  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, current, total);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr("50%"));
  EXPECT_THAT(output, HasSubstr("4194304KiB / 8388608KiB"));
  // 4GiB / 10s = 4096MiB / 10s = 409.6 MiB/s = 419430.4 KiB/s approx in double
  EXPECT_THAT(output, HasSubstr("419430 KiB/sec"));
}

TEST_F(ProgressTest, ZeroSpeed) {
  // Tests behavior when time advances but no bytes have been transferred yet.
  // This verifies that we don't divide by zero when calculating remaining time
  // and that we print sensible "0" values.
  mock_time.tv_sec = 10;

  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 0, 100);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_THAT(output, HasSubstr(" 0 KiB/sec"));
  EXPECT_THAT(output, HasSubstr(" 0 s remaining"));
}

TEST_F(ProgressTest, NoTtyNoOutput) {
  progress_.is_tty = false;

  testing::internal::CaptureStderr();
  progress_.progress.func(progress_.progress.param, 0, 100);
  std::string output = testing::internal::GetCapturedStderr();

  EXPECT_TRUE(output.empty());
}

}  // namespace
