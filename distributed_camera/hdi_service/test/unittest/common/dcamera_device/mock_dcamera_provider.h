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

#ifndef OHOS_MOCK_DCAMERA_PROVIDER_H
#define OHOS_MOCK_DCAMERA_PROVIDER_H

#include "dcamera_provider.h"

namespace OHOS {
namespace DistributedHardware {

extern std::string g_providerMockRet;

class MockDCameraProvider : public DCameraProvider {
public:
    MockDCameraProvider() = default;
    ~MockDCameraProvider() = default;

    static void SetInstance(const sptr<DCameraProvider>& instance)
    {
        DCameraProvider::instance_ = instance;
    }

    int32_t OpenSession(const DHBase& dhBase)
    {
        if (g_providerMockRet == "OpenSession_Fail") {
            return DCamRetCode::FAILED;
        }
        return CamRetCode::NO_ERROR;
    }

    int32_t CloseSession(const DHBase& dhBase)
    {
        return CamRetCode::NO_ERROR;
    }

    int32_t UpdateSettings(const DHBase& dhBase, const std::vector<DCameraSettings>& settings)
    {
        if (g_providerMockRet == "UpdateSettings_Fail") {
            return DCamRetCode::FAILED;
        }
        return CamRetCode::NO_ERROR;
    }

    int32_t StopCapture(const DHBase& dhBase, const std::vector<int>& streamIds)
    {
        return CamRetCode::NO_ERROR;
    }
};

} // namespace DistributedHardware
} // namespace OHOS

#endif // OHOS_MOCK_DCAMERA_PROVIDER_H
