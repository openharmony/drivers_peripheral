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

#include <errno.h>
#include "i_trigger.h"
#include "hdf_base.h"
#include "intell_voice_log.h"

#define LOG_TAG "IntellVoiceTriggerStub"
using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;
using namespace OHOS::IntellVoiceTrigger;


namespace OHOS {
namespace IntellVoiceTriggerStub {
class IntellVoiceTriggerManagerStub final : public ITriggerManager {
public:
    int32_t LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
        std::unique_ptr<ITrigger> &adapter) override
    {
        INTELL_VOICE_LOG_INFO("load adapter stub");
        return 0;
    }

    int32_t UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor) override
    {
        INTELL_VOICE_LOG_INFO("unload adapter stub");
        return 0;
    }

    static IntellVoiceTriggerManagerStub* GetInstance()
    {
        static IntellVoiceTriggerManagerStub trigger;
        return &trigger;
    }
private:
    IntellVoiceTriggerManagerStub() {};
    ~IntellVoiceTriggerManagerStub() {};
};

}
}

#ifdef __cplusplus
extern "C" {
#endif
__attribute__ ((visibility ("default")))
OHOS::IntellVoiceTrigger::ITriggerManager* GetIntellVoiceTriggerHalInst(void)
{
    INTELL_VOICE_LOG_INFO("enter to intell voice trigger stub");
    return OHOS::IntellVoiceTriggerStub::IntellVoiceTriggerManagerStub::GetInstance();
}

#ifdef __cplusplus
}
#endif
