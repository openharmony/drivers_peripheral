/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HDF_I_DAUDIO_HDF_CALLBACK_H
#define HDF_I_DAUDIO_HDF_CALLBACK_H

#include <string>
#include "types.h"

namespace OHOS {
namespace DistributedHardware {
class IDAudioHDFCallback {
public:
    virtual int32_t OpenDevice(int32_t devId, int32_t dhId) = 0;
    virtual int32_t CloseDevice(int32_t devId, int32_t dhId = 0;
    virtual int32_t SetParameters(int32_t devId, int32_t dhId, struct AudioParameter &param) = 0;
    virtual int32_t NotifyEvent(int32_t devId, int32_t dhId, struct DAudioEvent &event) = 0;
    virtual int32_t WriteStreamData(int32_t devId, int32_t dhId, struct AudioStreamData &data) = 0;
    virtual struct AudioStreamData* ReadStreamData(int32_t devId, int32_t dhId) = 0;
    virtual int32_t ReadMmapPosition(int32_t devId, int32_t dhId,
        uint64_t &frames, struct CurrentTime &time) = 0;
    virtual int32_t RefreshAshmemInfo(int32_t devId, int32_t dhId,
        int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans) = 0;
} // namespace DistributedHardware
} // namespace OHOS
} // HDF_I_DAUDIO_HDF_CALLBACK_H
#endif