/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cerrno>
#include "hdf_base.h"
#include "i_trigger.h"
#include "intell_voice_log.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceTriggerMgr"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
class IntellVoiceTriggerManager final : public ITriggerManager {
public:
    int32_t LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
        std::unique_ptr<ITrigger> &adapter) override
    {
        INTELLIGENT_VOICE_LOGD("load adapter stub");
        return HDF_SUCCESS;
    }

    int32_t UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor) override
    {
        INTELLIGENT_VOICE_LOGD("unload adapter stub");
        return HDF_SUCCESS;
    }

    static IntellVoiceTriggerManager *GetInstance()
    {
        static IntellVoiceTriggerManager trigger;
        return &trigger;
    }
private:
    IntellVoiceTriggerManager() {};
    ~IntellVoiceTriggerManager() {};
};
}
}
}

#ifdef __cplusplus
extern "C" {
#endif
__attribute__ ((visibility ("default"))) OHOS::IntelligentVoice::Trigger::ITriggerManager *GetIntellVoiceTriggerHalInst(void)
{
    INTELLIGENT_VOICE_LOGD("enter to intell voice trigger stub");
    return OHOS::IntelligentVoice::Trigger::IntellVoiceTriggerManager::GetInstance();
}
#ifdef __cplusplus
}
#endif
