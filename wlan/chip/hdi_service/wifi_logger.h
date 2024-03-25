/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WIFI_HAL_LOGGER_H
#define WIFI_HAL_LOGGER_H

#include "wifi_hal.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum {
    WIFI_LOGGER_MEMORY_DUMP_SUPPORTED = (1 << (0)),
    WIFI_LOGGER_PER_PACKET_TX_RX_STATUS_SUPPORTED = (1 << (1)),
    WIFI_LOGGER_CONNECT_EVENT_SUPPORTED = (1 << (2)),
    WIFI_LOGGER_POWER_EVENT_SUPPORTED = (1 << (3)),
    WIFI_LOGGER_WAKE_LOCK_SUPPORTED = (1 << (4)),
    WIFI_LOGGER_VERBOSE_SUPPORTED = (1 << (5)),
    WIFI_LOGGER_WATCHDOG_TIMER_SUPPORTED = (1 << (6)),
    WIFI_LOGGER_DRIVER_DUMP_SUPPORTED = (1 << (7)),
    WIFI_LOGGER_PACKET_FATE_SUPPORTED = (1 << (8)),
};

#ifdef __cplusplus
}
#endif
#endif