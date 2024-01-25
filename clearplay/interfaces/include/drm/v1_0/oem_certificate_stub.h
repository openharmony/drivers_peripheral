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

#ifndef OHOS_HDI_DRM_V1_0_OEMCERTIFICATESTUB_H
#define OHOS_HDI_DRM_V1_0_OEMCERTIFICATESTUB_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <object_collector.h>
#include <refbase.h>
#include "v1_0/ioem_certificate.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;
class OemCertificateStub : public IPCObjectStub {
public:
    explicit OemCertificateStub(const sptr<IOemCertificate> &impl);
    virtual ~OemCertificateStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static int32_t OemCertificateStubGenerateOemKeySystemRequest_(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption, sptr<OHOS::HDI::Drm::V1_0::IOemCertificate> impl);

    static int32_t OemCertificateStubProcessOemKeySystemResponse_(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption, sptr<OHOS::HDI::Drm::V1_0::IOemCertificate> impl);

    static int32_t OemCertificateStubGetVersion_(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption, sptr<OHOS::HDI::Drm::V1_0::IOemCertificate> impl);

private:
    int32_t OemCertificateStubGenerateOemKeySystemRequest(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption);

    int32_t OemCertificateStubProcessOemKeySystemResponse(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption);

    int32_t OemCertificateStubGetVersion(MessageParcel& oemCertificateData, MessageParcel& oemCertificateReply, MessageOption& oemCertificateOption);


    static inline ObjectDelegator<OHOS::HDI::Drm::V1_0::OemCertificateStub, OHOS::HDI::Drm::V1_0::IOemCertificate> objDelegator_;
    sptr<OHOS::HDI::Drm::V1_0::IOemCertificate> impl_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_OEMCERTIFICATESTUB_H