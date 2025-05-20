/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_MANAGER_INTERDFACE_IMPL_H
#define OHOS_DAUDIO_MANAGER_INTERDFACE_IMPL_H

#include <mutex>

#include <v2_0/id_audio_manager.h>

#include "audio_manager_interface_impl.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V2_0 {
using OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent;

class DAudioManagerInterfaceImpl : public IDAudioManager {
public:
    static DAudioManagerInterfaceImpl *GetDAudioManager()
    {
        if (dAudioMgr_ == nullptr) {
            std::unique_lock<std::mutex> mgr_mutex(mgrMtx_);
            if (dAudioMgr_ == nullptr) {
                dAudioMgr_ = new DAudioManagerInterfaceImpl();
            }
        }
        return dAudioMgr_;
    }

    ~DAudioManagerInterfaceImpl() override;

    int32_t RegisterAudioDevice(const std::string &adpName, int32_t devId, const std::string &capability,
        const sptr<IDAudioCallback> &callbackObj) override;

    int32_t UnRegisterAudioDevice(const std::string &adpName, int32_t devId) override;

    int32_t NotifyEvent(const std::string &adpName, int32_t devId, int32_t streamId, const DAudioEvent &event) override;

    int32_t RegisterAudioHdfListener(const std::string &serviceName,
        const sptr<IDAudioHdfCallback> &callbackObj) override;

    int32_t UnRegisterAudioHdfListener(const std::string &serviceName) override;

private:
    DAudioManagerInterfaceImpl();

    DAudioManagerInterfaceImpl(const DAudioManagerInterfaceImpl &);

    DAudioManagerInterfaceImpl &operator = (const DAudioManagerInterfaceImpl &);

private:
    class Deletor {
    public:
        ~Deletor()
        {
            if (DAudioManagerInterfaceImpl::dAudioMgr_ != nullptr) {
                delete DAudioManagerInterfaceImpl::dAudioMgr_;
            }
        };
    };
    static Deletor deletor;

private:
    OHOS::HDI::DistributedAudio::Audio::V1_0::AudioManagerInterfaceImpl *audioMgr_;
    static DAudioManagerInterfaceImpl *dAudioMgr_;
    static std::mutex mgrMtx_;
};
} // V2_0
} // AudioExt
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_DAUDIO_MANAGER_INTERDFACE_IMPL_H
