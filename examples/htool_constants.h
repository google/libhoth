// Copyright 2023 Google LLC
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

#ifndef THIRD_PARTY_LIBHOTH_LIBHOTH_EXAMPLES_HTOOL_CONSTANTS_H_
#define THIRD_PARTY_LIBHOTH_LIBHOTH_EXAMPLES_HTOOL_CONSTANTS_H_

#include <stdint.h>

#define BIT(nr) (1UL << (nr))
/* Hoth Reset causes */
const uint32_t kResetFlagOther = BIT(0);      /* Other known reason */
const uint32_t kResetFlagResetPin = BIT(1);   /* Reset pin asserted */
const uint32_t kResetFlagBrownout = BIT(2);   /* Brownout */
const uint32_t kResetFlagPowerOn = BIT(3);    /* Power-On reset */
const uint32_t kResetFlagWatchdog = BIT(4);   /* Watchdog timer reset */
const uint32_t kResetFlagSoft = BIT(5);       /* Soft reset trigger by core */
const uint32_t kResetFlagHibernate = BIT(6);  /* Wake from hibernate */
const uint32_t kResetFlagRtcAlarm = BIT(7);   /* RTC alarm wake */
const uint32_t kResetFlagWakePin = BIT(8);    /* Wake pin triggered wake */
const uint32_t kResetFlagLowBattery = BIT(9); /* Low battery triggered wake */
const uint32_t kResetFlagSysjump = BIT(10); /* Jumped directly to this image */
const uint32_t kResetFlagHard = BIT(11);    /* Hard reset from software */
const uint32_t kResetFlagApOff = BIT(12);   /* Do not power on AP */
const uint32_t kResetFlagPreserved = BIT(13);  /* Some reset flags preserved  */
                                               /* from previous boot */
const uint32_t kResetFlagUsbResume = BIT(14);  /* USB Resume triggered wake */
const uint32_t kResetFlagRdd = BIT(15);        /* USB Type-C debug cable */
const uint32_t kResetFlagRbox = BIT(16);       /* Fixed reset functionality */
const uint32_t kResetFlagSecurity = BIT(17);   /* Security threat */
const uint32_t kResetFlagApWatchdog = BIT(18); /* AP watchdog reset */

#endif  // THIRD_PARTY_LIBHOTH_LIBHOTH_EXAMPLES_HTOOL_CONSTANTS_H_
