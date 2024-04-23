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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSTUB_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/imedia_key_system_factory.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class MediaKeySystemFactoryStub : public IPCObjectStub {
public:
    explicit MediaKeySystemFactoryStub(const sptr<IMediaKeySystemFactory> &impl);
    virtual ~MediaKeySystemFactoryStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t MediaKeySystemFactoryStubIsMediaKeySystemSupported_(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> impl);

    static int32_t MediaKeySystemFactoryStubCreateMediaKeySystem_(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> impl);

    static int32_t MediaKeySystemFactoryStubGetMediaKeySystemDescription_(MessageParcel& mediaKeySystemFactoryData,
        MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption,
        sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> impl);

    static int32_t MediaKeySystemFactoryStubGetVersion_(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> impl);

private:
    int32_t MediaKeySystemFactoryStubIsMediaKeySystemSupported(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption);

    int32_t MediaKeySystemFactoryStubCreateMediaKeySystem(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption);

    int32_t MediaKeySystemFactoryStubGetMediaKeySystemDescription(MessageParcel& mediaKeySystemFactoryData,
        MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption);

    int32_t MediaKeySystemFactoryStubGetVersion(MessageParcel& mediaKeySystemFactoryData, MessageParcel& mediaKeySystemFactoryReply, MessageOption& mediaKeySystemFactoryOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::MediaKeySystemFactoryStub, OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSTUB_H