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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKSTUB_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKSTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/imedia_key_session_callback.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class MediaKeySessionCallbackStub : public IPCObjectStub {
public:
    explicit MediaKeySessionCallbackStub(const sptr<IMediaKeySessionCallback> &impl);
    virtual ~MediaKeySessionCallbackStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t MediaKeySessionCallbackStubSendEvent_(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> impl);

    static int32_t MediaKeySessionCallbackStubSendEventKeyChange_(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> impl);

    static int32_t MediaKeySessionCallbackStubGetVersion_(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption, sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> impl);

private:
    int32_t MediaKeySessionCallbackStubSendEvent(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption);

    int32_t MediaKeySessionCallbackStubSendEventKeyChange(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption);

    int32_t MediaKeySessionCallbackStubGetVersion(MessageParcel& mediaKeySessionCallbackData, MessageParcel& mediaKeySessionCallbackReply, MessageOption& mediaKeySessionCallbackOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::MediaKeySessionCallbackStub, OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKSTUB_H