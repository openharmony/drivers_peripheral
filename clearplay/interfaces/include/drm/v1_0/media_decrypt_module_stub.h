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

#ifndef OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESTUB_H
#define OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/imedia_decrypt_module.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class MediaDecryptModuleStub : public IPCObjectStub {
public:
    explicit MediaDecryptModuleStub(const sptr<IMediaDecryptModule> &impl);
    virtual ~MediaDecryptModuleStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t MediaDecryptModuleStubDecryptMediaData_(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption, sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> impl);

    static int32_t MediaDecryptModuleStubRelease_(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption, sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> impl);

    static int32_t MediaDecryptModuleStubGetVersion_(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption, sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> impl);

private:
    int32_t MediaDecryptModuleStubDecryptMediaData(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption);

    int32_t MediaDecryptModuleStubRelease(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption);

    int32_t MediaDecryptModuleStubGetVersion(MessageParcel& mediaDecryptModuleData, MessageParcel& mediaDecryptModuleReply, MessageOption& mediaDecryptModuleOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::MediaDecryptModuleStub, OHOS::HDI::Drm::V1_0::IMediaDecryptModule> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESTUB_H