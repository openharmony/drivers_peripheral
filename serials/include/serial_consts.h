/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_CONST_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_CONST_H


namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

constexpr int32_t BR50 = 50;
constexpr int32_t BR75 = 75;
constexpr int32_t BR110 = 110;
constexpr int32_t BR134 = 134;
constexpr int32_t BR150 = 150;
constexpr int32_t BR200 = 200;
constexpr int32_t BR300 = 300;
constexpr int32_t BR600 = 600;
constexpr int32_t BR1200 = 1200;
constexpr int32_t BR1800 = 1800;
constexpr int32_t BR2400 = 2400;
constexpr int32_t BR4800 = 4800;
constexpr int32_t BR9600 = 9600;
constexpr int32_t BR19200 = 19200;
constexpr int32_t BR38400 = 38400;
constexpr int32_t BR57600 = 57600;
constexpr int32_t BR115200 = 115200;
constexpr int32_t BR230400 = 230400;
constexpr int32_t BR460800 = 460800;
constexpr int32_t BR500000 = 500000;
constexpr int32_t BR576000 = 576000;
constexpr int32_t BR921600 = 921600;
constexpr int32_t BR1000000 = 1000000;
constexpr int32_t BR1152000 = 1152000;
constexpr int32_t BR1500000 = 1500000;
constexpr int32_t BR2000000 = 2000000;
constexpr int32_t BR2500000 = 2500000;
constexpr int32_t BR3000000 = 3000000;
constexpr int32_t BR3500000 = 3500000;
constexpr int32_t BR4000000 = 4000000;
constexpr int32_t MAX_BUFFER_LEN = 4096;
constexpr int32_t PIPE_READ_IDX = 0;
constexpr int32_t PIPE_WRITE_IDX = 1;
constexpr int32_t DATA_BIT_5 = 5;
constexpr int32_t DATA_BIT_6 = 6;
constexpr int32_t DATA_BIT_7 = 7;
constexpr int32_t DATA_BIT_8 = 8;
constexpr int32_t INVALID_FD = -1;
constexpr int32_t READ_WAIT_TIME = 5000;
constexpr int32_t FLAG_PARITY_0 = 0;
constexpr int32_t FLAG_PARITY_1 = 1;
constexpr int32_t FLAG_PARITY_2 = 2;
constexpr int32_t FLAG_PARITY_3 = 3;
constexpr int32_t FLAG_PARITY_4 = 4;
constexpr int32_t ARRAY_INDEX_0 = 0;
constexpr int32_t ARRAY_INDEX_1 = 1;
constexpr int32_t ARRAY_INDEX_2 = 2;
constexpr int32_t PIPE_FD_LEN = 2;
constexpr int32_t POLL_FDS_COUNT_READ = 3;
constexpr int32_t BASE_HEX = 16;
constexpr int32_t MAX_SYS_FILE_BUFF = 256;
constexpr int32_t BYTE_SIZE_ONE = 1;
constexpr int32_t STOP_BIT_ONE = 1;
constexpr int32_t STOP_BIT_TWO = 2;
constexpr int32_t VMIN_DEFAULT = 1;
constexpr int32_t UEVENT_MSG_LEN = 2048;
constexpr int32_t UEVENT_SOCKET_GROUPS = 0xffffffff;
constexpr int32_t UEVENT_SOCKET_BUFF_SIZE = (64 * 1024);
constexpr int32_t UEVENT_POLL_WAIT_TIME = 100;
constexpr int32_t MAX_ERR_TIMES = 10;
constexpr int32_t MAX_UEVENT_BIND_RETRY_TIMES = 50;
} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_CONST_H
