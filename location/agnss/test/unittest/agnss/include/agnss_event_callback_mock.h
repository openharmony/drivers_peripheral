/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AGNSS_EVENT_CALLBACK_MOCK_H
#define AGNSS_EVENT_CALLBACK_MOCK_H

#include "iremote_stub.h"
#include "iremote_object.h"
#include <hdf_base.h>

#include <iproxy_broker.h>
#include <v2_0/ia_gnss_callback.h>
#include "v2_0/ia_gnss_callback.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Agnss {
namespace V2_0 {

class IAgnssEventCallback : public IAGnssCallback {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.location.agnss.v2_0.IAGnssCallback");
};

class AgnssEventCallbackMock : public IProxyBroker<IAgnssEventCallback> {
public:
    explicit AgnssEventCallbackMock(const sptr<IRemoteObject>& remote)
        : IProxyBroker<IAgnssEventCallback>(remote) {
    }
    int32_t RequestSetUpAgnssDataLink(const OHOS::HDI::Location::Agnss::V2_0::AGnssDataLinkRequest& request) override;

    int32_t RequestSubscriberSetId(OHOS::HDI::Location::Agnss::V2_0::SubscriberSetIdType type) override;

    int32_t RequestAgnssRefInfo(OHOS::HDI::Location::Agnss::V2_0::AGnssRefInfoType type) override;
};

} // V2_0
} // Agnss
} // Location
} // HDI
} // OHOS
#endif // AGNSS_EVENT_CALLBACK_MOCK_H
