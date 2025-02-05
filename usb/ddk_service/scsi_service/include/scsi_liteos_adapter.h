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

#ifndef SCSI_LITEOS_ADAPTER_H
#define SCSI_LITEOS_ADAPTER_H

#include "scsi_os_apdater.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

class LiteOsScsiOsAdapter : public ScsiOsAdapter {
public:
    LiteOsScsiOsAdapter() = default;
    virtual ~LiteOsScsiOsAdapter() = default;

    int32_t SendRequest(const Request& request, uint8_t *buffer, uint32_t bufferSize, Response& response) override;
};
} // namespace V1_0
} // namespace ScsiDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif