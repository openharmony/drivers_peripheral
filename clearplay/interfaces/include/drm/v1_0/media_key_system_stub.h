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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSTUB_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/imedia_key_system.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class MediaKeySystemStub : public IPCObjectStub {
public:
    explicit MediaKeySystemStub(const sptr<IMediaKeySystem> &impl);
    virtual ~MediaKeySystemStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t MediaKeySystemStubGetConfigurationString_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubSetConfigurationString_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetConfigurationByteArray_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubSetConfigurationByteArray_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetStatistics_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetMaxContentProtectionLevel_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGenerateKeySystemRequest_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubProcessKeySystemResponse_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetOemCertificateStatus_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubSetCallback_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubCreateMediaKeySession_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetOfflineMediaKeyIds_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetOfflineMediaKeyStatus_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubClearOfflineMediaKeys_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetOemCertificate_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubDestroy_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

    static int32_t MediaKeySystemStubGetVersion_(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl);

private:
    int32_t MediaKeySystemStubGetConfigurationString(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubSetConfigurationString(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetConfigurationByteArray(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubSetConfigurationByteArray(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetStatistics(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetMaxContentProtectionLevel(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGenerateKeySystemRequest(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubProcessKeySystemResponse(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetOemCertificateStatus(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubSetCallback(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubCreateMediaKeySession(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetOfflineMediaKeyIds(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetOfflineMediaKeyStatus(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubClearOfflineMediaKeys(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetOemCertificate(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubDestroy(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);

    int32_t MediaKeySystemStubGetVersion(MessageParcel& mediaKeySystemData, MessageParcel& mediaKeySystemReply, MessageOption& mediaKeySystemOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::MediaKeySystemStub, OHOS::HDI::Drm::V1_0::IMediaKeySystem> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSTUB_H