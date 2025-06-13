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

#ifndef OHOS_HDI_CODEC_V4_0_CODECDEATHRECIPIENT_H
#define OHOS_HDI_CODEC_V4_0_CODECDEATHRECIPIENT_H

#include <functional>
#include "iremote_object.h"
#include "refbase.h"
#include "codec_component_manager_service.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V4_0 {

void CleanResourceOfDiedService(sptr<IRemoteObject> remote, wptr<CodecComponentManagerService> service);
void RegisterDeathRecipientService(const sptr<ICodecCallback> callback, uint32_t componentId,
                                   wptr<CodecComponentManagerService> service);
void RemoveMapperOfDestoryedComponent(uint32_t componentId);

class CodecDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CodecDeathRecipient(const wptr<CodecComponentManagerService> &service) : mgr(service) {};
    virtual ~CodecDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        sptr<IRemoteObject> remote = object.promote();
        if (remote == nullptr) {
            return;
        }
        CleanResourceOfDiedService(remote, mgr);
    };
private:
    wptr<CodecComponentManagerService> mgr;
};

}  // namespace V4_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS

#endif  // OHOS_HDI_CODEC_V4_0_CODECDEATHRECIPIENT_H
