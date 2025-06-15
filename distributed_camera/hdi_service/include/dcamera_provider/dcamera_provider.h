/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_CAMERA_PROVIDER_H
#define DISTRIBUTED_CAMERA_PROVIDER_H

#include "v1_1/id_camera_provider.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedCamera::V1_1;
class DCameraHost;
class DCameraDevice;
class DCameraProvider : public IDCameraProvider {
const uint32_t ABILITYINFO_MAX_LENGTH = 50 * 1024 * 1024;
const uint32_t HDF_EVENT_CONTENT_MAX_LENGTH = 50 * 1024 * 1024;
const uint32_t SETTING_VALUE_MAX_LENGTH = 50 * 1024 * 1024;
public:
    DCameraProvider() = default;
    ~DCameraProvider() override = default;
    DCameraProvider(const DCameraProvider &other) = delete;
    DCameraProvider(DCameraProvider &&other) = delete;
    DCameraProvider& operator=(const DCameraProvider &other) = delete;
    DCameraProvider& operator=(DCameraProvider &&other) = delete;

public:
    static OHOS::sptr<DCameraProvider> GetInstance();
    int32_t EnableDCameraDevice(const DHBase& dhBase, const std::string& abilityInfo,
        const sptr<IDCameraProviderCallback>& callbackObj) override;
    int32_t DisableDCameraDevice(const DHBase& dhBase) override;
    int32_t AcquireBuffer(const DHBase& dhBase, int32_t streamId, DCameraBuffer& buffer) override;
    int32_t ShutterBuffer(const DHBase& dhBase, int32_t streamId, const DCameraBuffer& buffer) override;
    int32_t OnSettingsResult(const DHBase& dhBase, const DCameraSettings& result) override;
    int32_t Notify(const DHBase& dhBase, const DCameraHDFEvent& event) override;
    int32_t RegisterCameraHdfListener(const std::string &serviceName,
        const sptr<IDCameraHdfCallback> &callbackObj) override;
    int32_t UnRegisterCameraHdfListener(const std::string &serviceName) override;

    int32_t OpenSession(const DHBase &dhBase);
    int32_t CloseSession(const DHBase &dhBase);
    int32_t ConfigureStreams(const DHBase &dhBase, const std::vector<DCStreamInfo> &streamInfos);
    int32_t ReleaseStreams(const DHBase &dhBase, const std::vector<int> &streamIds);
    int32_t StartCapture(const DHBase &dhBase, const std::vector<DCCaptureInfo> &captureInfos);
    int32_t StopCapture(const DHBase &dhBase, const std::vector<int> &streamIds);
    int32_t UpdateSettings(const DHBase &dhBase, const std::vector<DCameraSettings> &settings);

private:
    bool IsDCameraSettingsInvalid(const DCameraSettings& result);
    bool IsDCameraHDFEventInvalid(const DCameraHDFEvent& event);
    sptr<IDCameraProviderCallback> GetCallbackBydhBase(const DHBase &dhBase);
    OHOS::sptr<DCameraDevice> GetDCameraDevice(const DHBase &dhBase);
    bool GetAbilityInfo(const std::string& abilityInfo, std::string& sinkAbilityInfo,
        std::string& sourceCodecInfo);

private:
    class AutoRelease {
    public:
        AutoRelease() {}
        ~AutoRelease()
        {
            if (DCameraProvider::instance_ != nullptr) {
                DCameraProvider::instance_ = nullptr;
            }
        }
    };
    static AutoRelease autoRelease_;
    static OHOS::sptr<DCameraProvider> instance_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_PROVIDER_H