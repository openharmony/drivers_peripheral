/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_NEARLINK_DLI_V1_1_VENDOR_INTERFACE_H
#define OHOS_HDI_NEARLINK_DLI_V1_1_VENDOR_INTERFACE_H

#include <functional>
#include <shared_mutex>
#include <vector>

#include "singleton.h"

#include "dli_internal.h"
#include "dli_protocol.h"
#include "dli_watcher.h"
#include "ohos_sle_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
namespace V1_1 {
class VendorInterface : public DelayedSingleton<VendorInterface>,
    public std::enable_shared_from_this<VendorInterface> {
public:
    using InitializeCompleteCallback = std::function<void(bool isSuccess)>;
    using ReceiveDataCallback = Dli::DliProtocol::DliDataCallback;
    struct ReceiveCallback {
        ReceiveDataCallback onAcbReceive;
        ReceiveDataCallback onIcbReceive;
        ReceiveDataCallback onEventReceive;
    };

    bool Initialize(InitializeCompleteCallback initializeCompleteCallback, const ReceiveCallback &receiveCallback);
    void CleanUp();
    size_t SendPacket(const std::vector<uint8_t> &packet);

private:
    // callback function
    void OnEventReceived(const std::vector<uint8_t> &data);
    void OnAcbReceived(const std::vector<uint8_t> &data);
    void OnIcbReceived(const std::vector<uint8_t> &data);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    std::shared_mutex vendorMutex_;
    std::weak_ptr<VendorInterface> vendorInterfaceWeak_;

    DECLARE_DELAYED_SINGLETON(VendorInterface);
    DISALLOW_COPY_AND_MOVE(VendorInterface);
};
}  // namespace V1_1
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_Nearlink_DLI_V1_1_VENDOR_INTERFACE_H */