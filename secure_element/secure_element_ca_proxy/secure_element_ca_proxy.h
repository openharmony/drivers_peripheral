/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef SECURE_ELEMENT_CA_PROXY_H
#define SECURE_ELEMENT_CA_PROXY_H

#include <dlfcn.h>
#include <hdf_log.h>
#include <memory>
#include <string>

enum SECURE_ELEMENT_CA_RET {
    SECURE_ELEMENT_CA_RET_OK = 0,
    SECURE_ELEMENT_CA_RET_CONTEXT_FAIL = 1,
    SECURE_ELEMENT_CA_RET_MEMSET_FAIL,
    SECURE_ELEMENT_CA_RET_TEE_UNINITED,
    SECURE_ELEMENT_CA_RET_ESE_CONFIG_FAIL,
    SECURE_ELEMENT_CA_RET_END,
    SECURE_ELEMENT_CA_RET_LOAD_FAIL,
};

namespace OHOS {
namespace HDI {
namespace SecureElement {
class SecureElementCaProxy {
public:
    ~SecureElementCaProxy() = default;

    SecureElementCaProxy(const SecureElementCaProxy &) = delete;
    SecureElementCaProxy &operator=(SecureElementCaProxy &) = delete;

    static SecureElementCaProxy &GetInstance()
    {
        static SecureElementCaProxy instance;
        return instance;
    }

    int VendorSecureElementCaOnStart() const;
    int VendorSecureElementCaInit() const;
    int VendorSecureElementCaUninit() const;
    int VendorSecureElementCaGetAtr(uint8_t *rsp, uint32_t *rspLen) const;
    int VendorSecureElementCaOpenLogicalChannel(
        uint8_t *aid, uint32_t len, uint8_t p2, uint8_t *rsp, uint32_t *rspLen, uint32_t *channelNum) const;
    int VendorSecureElementCaOpenBasicChannel(uint8_t *aid, uint32_t len, uint8_t *rsp, uint32_t *rspLen) const;
    int VendorSecureElementCaCloseChannel(uint32_t channelNum) const;
    int VendorSecureElementCaTransmit(uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp, uint32_t *rspLen) const;

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
        void *handle_{nullptr};
        std::string libPath_;
    };

    using VendorSecureElementCaInitT = int (*)(void);
    using VendorSecureElementCaUninitT = int (*)(void);
    using VendorSecureElementCaGetAtrT = int (*)(uint8_t *rsp, uint32_t *rspLen);
    using VendorSecureElementCaOpenLogicalChannelT = int (*)(uint8_t *aid, uint32_t len, uint8_t p2, uint8_t *rsp,
                                                            uint32_t *rspLen, uint32_t *channelNum);
    using VendorSecureElementCaOpenBasicChannelT = int (*)(uint8_t *aid, uint32_t len, uint8_t *rsp, uint32_t *rspLen);
    using VendorSecureElementCaCloseChannelT = int (*)(uint32_t channelNum);
    using VendorSecureElementCaTransmitT = int (*)(uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp, uint32_t *rspLen);
    using VendorSecureElementCaOnStartT = int (*)(void);
    const char *const LIB_NAME = "libsecure_element_ca.z.so";
    const char *const CA_INIT_SYMBOL = "VendorSecureElementCaInit";
    const char *const CA_UNINIT_SYMBOL = "VendorSecureElementCaUninit";
    const char *const CA_GET_ATR_SYMBOL = "VendorSecureElementCaGetAtr";
    const char *const CA_OPEN_LOGICAL_SYMBOL = "VendorSecureElementCaOpenLogicalChannel";
    const char *const CA_OPEN_BASIC_SYMBOL = "VendorSecureElementCaOpenBasicChannel";
    const char *const CA_CLOSE_SYMBOL = "VendorSecureElementCaCloseChannel";
    const char *const CA_TRANS_SYMBOL = "VendorSecureElementCaTransmit";
    const char *const CA_ON_START_SYMBOL = "VendorSecureElementOnStart";

    SecureElementCaProxy();

    void InitFunc();
    VendorSecureElementCaOnStartT vendorSecureElementCaOnStartFunc_{nullptr};
    VendorSecureElementCaInitT vendorSecureElementCaInitFunc_{nullptr};
    VendorSecureElementCaUninitT vendorSecureElementCaUninitFunc_{nullptr};
    VendorSecureElementCaGetAtrT vendorSecureElementCaGetAtrFunc_{nullptr};
    VendorSecureElementCaOpenLogicalChannelT vendorSecureElementCaOpenLogicalChannelFunc_{nullptr};
    VendorSecureElementCaOpenBasicChannelT vendorSecureElementCaOpenBasicChannelFunc_{nullptr};
    VendorSecureElementCaCloseChannelT vendorSecureElementCaCloseChannelFunc_{nullptr};
    VendorSecureElementCaTransmitT vendorSecureElementCaTransmitFunc_{nullptr};
    static inline std::unique_ptr<DynamicLoad> loader_;
};

}  // SecureElement
}  // HDI
}  // OHOS

#endif