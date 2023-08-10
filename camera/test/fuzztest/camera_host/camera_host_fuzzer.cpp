/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "camera.h"
#include "camera_host_fuzzer.h"

namespace OHOS {
const size_t THRESHOLD = 10;

enum HostCmdId {
    CAMERA_DEVICE_PRELAUNCH,
};

enum BitOperat {
    INDEX_0 = 0,
    INDEX_1,
    INDEX_2,
    INDEX_3,
    MOVE_EIGHT_BITS = 8,
    MOVE_SIXTEEN_BITS = 16,
    MOVE_TWENTY_FOUR_BITS = 24,
};

static uint32_t ConvertUint32(const uint8_t *bitOperat)
{
    if (bitOperat == nullptr) {
        return 0;
    }

    return (bitOperat[INDEX_0] << MOVE_TWENTY_FOUR_BITS)
        | (bitOperat[INDEX_1] << MOVE_SIXTEEN_BITS) | (bitOperat[INDEX_2] << MOVE_EIGHT_BITS)
        | (bitOperat[INDEX_3]);
}

static void HostFuncSwitch(uint32_t cmd, const uint8_t *&rawData)
{
    switch (cmd) {
        case CAMERA_DEVICE_PRELAUNCH: {
            cameraTest->serviceV1_1->Prelaunch(reinterpret_cast<const HDI::Camera::V1_1::PrelaunchConfig&>(rawData));
        }
            break;
        default:
            return;
    }
}

bool DoSomethingInterestingWithMyApi(const uint8_t *rawData, size_t size)
{
    (void)size;
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = ConvertUint32(rawData);
    rawData += sizeof(cmd);

    cameraTest = std::make_shared<OHOS::Camera::CameraManager>();
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return false;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return false;
    }

    HostFuncSwitch(cmd, rawData);
    cameraTest->Close();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
}
