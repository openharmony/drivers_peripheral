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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSTUB_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/imedia_key_session.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class MediaKeySessionStub : public IPCObjectStub {
public:
    explicit MediaKeySessionStub(const sptr<IMediaKeySession> &impl);
    virtual ~MediaKeySessionStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t MediaKeySessionStubGenerateMediaKeyRequest_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubProcessMediaKeyResponse_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubCheckMediaKeyStatus_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubClearMediaKeys_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubGetOfflineReleaseRequest_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubProcessOfflineReleaseResponse_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubRestoreOfflineMediaKeys_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubGetContentProtectionLevel_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubRequiresSecureDecoderModule_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubSetCallback_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubGetMediaDecryptModule_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubDestroy_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

    static int32_t MediaKeySessionStubGetVersion_(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl);

private:
    int32_t MediaKeySessionStubGenerateMediaKeyRequest(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubProcessMediaKeyResponse(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubCheckMediaKeyStatus(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubClearMediaKeys(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubGetOfflineReleaseRequest(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubProcessOfflineReleaseResponse(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubRestoreOfflineMediaKeys(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubGetContentProtectionLevel(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubRequiresSecureDecoderModule(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubSetCallback(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubGetMediaDecryptModule(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubDestroy(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);

    int32_t MediaKeySessionStubGetVersion(MessageParcel& mediaKeySessionData, MessageParcel& mediaKeySessionReply, MessageOption& mediaKeySessionOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::MediaKeySessionStub, OHOS::HDI::Drm::V1_0::IMediaKeySession> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSTUB_H