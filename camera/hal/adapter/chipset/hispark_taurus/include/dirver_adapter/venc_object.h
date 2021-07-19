/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_VENC_OBJECT_H
#define HOS_CAMERA_VENC_OBJECT_H

#include <string>
#include "mpi_adapter.h"

extern "C" {
#include "hal_codec.h"
}

namespace OHOS::Camera {
class VencObject {
public:
    VencObject();
    ~VencObject();
    void ConfigVenc(uint32_t width, uint32_t height);
    void StartVenc() {};
    void StopVenc() {};
    void StartEncoder(HI_U32 mode, HI_U32 w, HI_U32 h);
    void EncoderProc(const void *buffer, std::string path);
    void StopEncoder();
    void dump();
private:
    int32_t vencChn;
};
}

#endif // HOS_CAMERA_VENC_OBJECT_H

