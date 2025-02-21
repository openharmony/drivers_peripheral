/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SCSI_OS_ADAPTER_H
#define SCSI_OS_ADAPTER_H

#include <stdint.h>
#include <vector>

#include "scsi_ddk_err_code.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

typedef struct Request {
    int devFd;
    std::vector<uint8_t> commandDescriptorBlock;
    int8_t dataTransferDirection;
    uint32_t timeout;
} Request;

typedef struct Response {
    std::vector<uint8_t> senseData;
    unsigned char status;
    unsigned char maskedStatus;
    unsigned char msgStatus;
    unsigned char sbLenWr;
    unsigned short hostStatus;
    unsigned short driverStatus;
    int resId;
    unsigned int duration;
    int transferredLength;
} Response;

class ScsiOsAdapter {
public:
    virtual int32_t SendRequest(const Request& request, uint8_t *buffer, uint32_t bufferSize, Response& response) = 0;
};

} // namespace V1_0
} // namespace ScsiDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif
