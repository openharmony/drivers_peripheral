/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SIM_SE_VENDOR_ADAPTIONS_H
#define SIM_SE_VENDOR_ADAPTIONS_H

#include "v1_0/isecure_element_interface.h"
#include <dlfcn.h>
#include <hdf_log.h>
#include <memory>
#include <string>

#include "remote_death_recipient.h"

enum SIM_SECURE_ELEMENT_RET {
    SIM_SECURE_ELEMENT_RET_OK = 0,
    SIM_SECURE_ELEMENT_RET_CONTEXT_FAIL = 1,
    SIM_SECURE_ELEMENT_RET_MEMSET_FAIL,
    SIM_SECURE_ELEMENT_RET_TEE_UNINITED,
    SIM_SECURE_ELEMENT_RET_ESE_CONFIG_FAIL,
    SIM_SECURE_ELEMENT_RET_LOAD_FAIL,
    SIM_SECURE_ELEMENT_RET_END,
};

namespace OHOS {
namespace HDI {
namespace SecureElement {
namespace SimSecureElement {
namespace V1_0 {
class SimSeVendorAdaptions {
public:
    SimSeVendorAdaptions();
    ~SimSeVendorAdaptions();

    int32_t init(const sptr<OHOS::HDI::SecureElement::SimSecureElement::V1_0::ISecureElementCallback>& clientCallback,
        OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);

    int32_t getAtr(std::vector<uint8_t>& response);

    int32_t isSecureElementPresent(bool& present);

    int32_t openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        uint8_t& channelNumber, OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);

    int32_t openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);

    int32_t closeChannel(uint8_t channelNumber,
        OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);

    int32_t transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
        OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);

    int32_t reset(OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status);
private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    int32_t AddSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj);
    int32_t RemoveSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj);

    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
private:
    class DynamicLoad {
    public:
        explicit DynamicLoad(const std::string &lib);
        ~DynamicLoad();
        DynamicLoad(const DynamicLoad &) = delete;
        DynamicLoad &operator=(DynamicLoad &) = delete;
        bool LoadLib();
        bool CloseLib();
        template <typename T>
        T FindTheFunc(const std::string &func)
        {
            if (!handle_) {
                HDF_LOGE("fail handle is null");
                return nullptr;
            }
            T newFunc = reinterpret_cast<T>(dlsym(handle_, func.c_str()));
            if (!newFunc) {
                HDF_LOGE("find func:%{public}s in %{public}s fail", func.c_str(), libPath_.c_str());
                return nullptr;
            }
            HDF_LOGI("find func:%{public}s in %{public}s success", func.c_str(), libPath_.c_str());
            return newFunc;
        }

    private:
        void *handle_{ nullptr };
        std::string libPath_;
    };
    using VendorSimSecureElementInitT = int (*)(void);
    using VendorSimSecureElementUninitT = int (*)(void);
    using VendorSimSecureElementIsCardPresentT = bool (*)(void);
    using VendorSimSecureElementGetAtrT = int (*)(uint8_t *rsp, uint32_t *rspLen);
    using VendorSimSecureElementOpenLogicalChannelT = int (*)(uint8_t *aid, uint32_t len, uint8_t p2, uint8_t *rsp,
        uint32_t *rspLen, uint32_t *channelNum, int *status);
    using VendorSimSecureElementOpenBasicChannelT = int (*)(uint8_t *aid, uint32_t len, uint8_t *rsp,
        uint32_t *rspLen, int *status);
    using VendorSimSecureElementCloseChannelT = int (*)(uint32_t channelNum, int *status);
    using VendorSimSecureElementTransmitT = int (*)(uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp,
        uint32_t *rspLen, int *status);
    const char *const LIB_NAME = "libsim_secure_element.z.so";
    const char *const SIM_INIT_SYMBOL = "VendorSimSecureElementInit";
    const char *const SIM_UNINIT_SYMBOL = "VendorSimSecureElementUninit";
    const char *const SIM_IS_CARD_PRESENT_SYMBOL = "VendorSimSecureElementIsCardPresent";
    const char *const SIM_GET_ATR_SYMBOL = "VendorSimSecureElementGetAtr";
    const char *const SIM_OPEN_LOGICAL_SYMBOL = "VendorSimSecureElementOpenLogicalChannel";
    const char *const SIM_OPEN_BASIC_SYMBOL = "VendorSimSecureElementOpenBasicChannel";
    const char *const SIM_CLOSE_SYMBOL = "VendorSimSecureElementCloseChannel";
    const char *const SIM_TRANS_SYMBOL = "VendorSimSecureElementTransmit";

    void InitFunc();
    VendorSimSecureElementInitT vendorSimSecureElementInitFunc_{nullptr};
    VendorSimSecureElementUninitT vendorSimSecureElementUninitFunc_{nullptr};
    VendorSimSecureElementIsCardPresentT vendorSimSecureElementIsCardPresentFunc_{nullptr};
    VendorSimSecureElementGetAtrT vendorSimSecureElementGetAtrFunc_{nullptr};
    VendorSimSecureElementOpenLogicalChannelT vendorSimSecureElementOpenLogicalChannelFunc_{nullptr};
    VendorSimSecureElementOpenBasicChannelT vendorSimSecureElementOpenBasicChannelFunc_{nullptr};
    VendorSimSecureElementCloseChannelT vendorSimSecureElementCloseChannelFunc_{nullptr};
    VendorSimSecureElementTransmitT vendorSimSecureElementTransmitFunc_{nullptr};
    static inline std::unique_ptr<DynamicLoad> loader_;

    int VendorSimSecureElementInit();
    int VendorSimSecureElementUninit();
    int VendorSimSecureElementGetAtr(uint8_t *rsp, uint32_t *rspLen);
    int VendorSimSecureElementOpenLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2,
        std::vector<uint8_t>& response, uint32_t *channelNum, int *status);
    int VendorSimSecureElementOpenBasicChannel(uint8_t *aid, uint32_t len, uint8_t *rsp, uint32_t *rspLen, int *status);
    int VendorSimSecureElementCloseChannel(uint32_t channelNum, int *status);
    int VendorSimSecureElementTransmit(uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp, uint32_t *rspLen, int *status);
};
} // V1_0
} // SimSecureElement
} // SecureElement
} // HDI
} // OHOS

#endif // SIM_SE_VENDOR_ADAPTIONS_H
