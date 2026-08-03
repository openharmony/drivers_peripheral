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

#include "connected_nfc_tag_vendor_adapter.h"

#include <cctype>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <hdf_log.h>
#include <dlfcn.h>

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000307
#define HDF_LOG_TAG NFCTAG_ADAPTER

namespace OHOS {
namespace HDI {
namespace ConnectedNfcTag {

namespace {
static const std::string NFC_HAL_VENDOR_SERVICE = "libnfc_tag_hal_vendor_service.z.so";
const std::string GET_CHIP_TYPE_FUNC_NAME = "NfcTagGetChipType";

const std::string NFC_HAL_SO_PREFIX = "libnfc_tag_hal_impl_";
const std::string NFC_HAL_SO_SUFFIX = ".z.so";

const std::string CHIP_INIT_FUNC_NAME = "NfcTagChipInit";
const std::string CHIP_UNINIT_FUNC_NAME = "NfcTagChipUnInit";
const std::string REGISTER_CALLBACK_FUNC_NAME = "NfcTagRegisterCallback";
const std::string WRITE_NDEF_FUNC_NAME = "NfcTagWriteNdefMessage";
const std::string READ_NDEF_FUNC_NAME = "NfcTagReadNdefMessage";

static const int MAX_NDEF_LEN = 256;
}

bool IsValidChipType(const std::string &type)
{
    if (type.empty()) {
        return false;
    }
    for (char c : type) {
        if (!std::isalnum(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

std::string GetNfcChipType(void)
{
    HDF_LOGE("%{public}s:begin", __func__);
    void *srvHandle = dlopen(NFC_HAL_VENDOR_SERVICE.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (srvHandle == nullptr) {
        HDF_LOGE("open %{public}s failed", NFC_HAL_VENDOR_SERVICE.c_str());
        return "";
    }

    VendorGetChipType getChipFunc = reinterpret_cast<const char* (*)()>
        (dlsym(srvHandle, GET_CHIP_TYPE_FUNC_NAME.c_str()));
    if (getChipFunc == nullptr) {
        HDF_LOGE("%{public}s: getChipFunc NULL", __func__);
        dlclose(srvHandle);
        return "";
    }
    
    const char* chipType = getChipFunc();
    if (chipType == nullptr || chipType[0] == '\0') {
        HDF_LOGW("%{public}s: chipType Invalid", __func__);
        chipType = "";
    }

    HDF_LOGE("%{public}s: end chipType %{public}s", __func__, chipType);
    // 调用dlcose后，对应so占用的内存会被释放，继续访问getChipFunc返回的字符串，调用者线程会crash
    std::string strChipType = chipType;
    dlclose(srvHandle);
    return strChipType;
}

bool CheckNfcChipType(const std::string &type)
{
    if (!IsValidChipType(type)) {
        HDF_LOGE("%{public}s: invalid chip type chars", __func__);
        return false;
    }
    static const std::string ALL_CHIP_TYPES[] = {
        "t000", "t001", "t002", "t003", "t004", "t005", "t006", "t007", "t008", "t009",
        "t010", "t011", "t012", "t013", "t014", "t015", "t016", "t017", "t018", "t019"
    };
    auto it = std::find(std::begin(ALL_CHIP_TYPES), std::end(ALL_CHIP_TYPES), type);
    return it != std::end(ALL_CHIP_TYPES);
}

ConnectedNfcTagVendorAdapter::ConnectedNfcTagVendorAdapter(): halHandle(nullptr)
{
    infHandle.init = nullptr;
    infHandle.unInit = nullptr;
    infHandle.registerCallBack = nullptr;
    infHandle.writeNdefData = nullptr;
    infHandle.readNdefData = nullptr;
}

ConnectedNfcTagVendorAdapter::~ConnectedNfcTagVendorAdapter()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infHandle.unInit) {
        infHandle.unInit();
    }
    infHandle.init = nullptr;
    infHandle.unInit = nullptr;
    infHandle.registerCallBack = nullptr;
    infHandle.writeNdefData = nullptr;
    infHandle.readNdefData = nullptr;
    if (halHandle != nullptr) {
        dlclose(halHandle);
        halHandle = nullptr;
    }
}

int32_t ConnectedNfcTagVendorAdapter::GetInterfaceFromHal()
{
    if (halHandle == nullptr) {
        HDF_LOGE("nfc halHandle == nullptr");
        return -1;
    }
    infHandle.init = reinterpret_cast<int32_t (*)()>
        (dlsym(halHandle, CHIP_INIT_FUNC_NAME.c_str()));
    if (infHandle.init == nullptr) {
        HDF_LOGE("%{public}s: init NULL", __func__);
        return -1;
    }

    infHandle.unInit = reinterpret_cast<int32_t (*)()>
        (dlsym(halHandle, CHIP_UNINIT_FUNC_NAME.c_str()));
    if (infHandle.unInit == nullptr) {
        HDF_LOGE("%{public}s: unInit NULL", __func__);
        infHandle.init = nullptr;
        return -1;
    }

    infHandle.registerCallBack = reinterpret_cast<int32_t (*)(NfcTagChipEventCallbackT *callback)>
        (dlsym(halHandle, REGISTER_CALLBACK_FUNC_NAME.c_str()));
    if (infHandle.registerCallBack == nullptr) {
        HDF_LOGE("%{public}s: registerCallBack NULL", __func__);
        infHandle.init = nullptr;
        infHandle.uninit = nullptr;
        return -1;
    }

    infHandle.writeNdefData = reinterpret_cast<int32_t (*)(const uint8_t *writeData, uint32_t writeLen)>
        (dlsym(halHandle, WRITE_NDEF_FUNC_NAME.c_str()));
    if (infHandle.writeNdefData == nullptr) {
        HDF_LOGE("%{public}s: writeNdefData NULL", __func__);
        infHandle.init = nullptr;
        infHandle.uninit = nullptr;
        infHandle.registerCallBack = nullptr;
        return -1;
    }

    infHandle.readNdefData = reinterpret_cast<int32_t (*)(uint8_t *readData, uint32_t *readLen)>
        (dlsym(halHandle, READ_NDEF_FUNC_NAME.c_str()));
    if (infHandle.readNdefData == nullptr) {
        HDF_LOGE("%{public}s: readNdefData NULL", __func__);
        infHandle.init = nullptr;
        infHandle.uninit = nullptr;
        infHandle.registerCallBack = nullptr;
        infHandle.writeNdefData = nullptr;
        return -1;
    }
    return 0;
}

int32_t ConnectedNfcTagVendorAdapter::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string nfcChipType = GetNfcChipType();
    if (nfcChipType == "") {
        HDF_LOGE("nfcChipType empty");
        return -1;
    }
    if (!CheckNfcChipType(nfcChipType)) {
        HDF_LOGE("nfcChipType not allowed");
        return -1;
    }

    if (halHandle != nullptr) {
        HDF_LOGE("nfc halHandle inited");
        return -1;
    }
    
    std::string halName = NFC_HAL_SO_PREFIX + nfcChipType + NFC_HAL_SO_SUFFIX;
    halHandle = dlopen(halName.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (halHandle == nullptr) {
        HDF_LOGE("%{public}s: dlopen %{public}s fail", __func__, halName.c_str());
        return -1;
    }
    
    if (GetInterfaceFromHal() != 0) {
        if (halHandle != nullptr) {
            dlclose(halHandle);
            halHandle = nullptr;
        }
        return -1;
    }

    if (infHandle.init() != 0) {
        HDF_LOGE("%{public}s: init Fail", __func__);
        if (infHandle.unInit) {
            infHandle.unInit();
        }
        if (halHandle != nullptr) {
            dlclose(halHandle);
            halHandle = nullptr;
        }
        return -1;
    }

    return 0;
}

int32_t ConnectedNfcTagVendorAdapter::UnInit()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (halHandle == nullptr) {
        HDF_LOGE("%{public}s: halHandle NULL", __func__);
        return -1;
    }

    if (infHandle.unInit) {
        infHandle.unInit();
    }

    infHandle.init = nullptr;
    infHandle.unInit = nullptr;
    infHandle.registerCallBack = nullptr;
    infHandle.writeNdefData = nullptr;
    infHandle.readNdefData = nullptr;
    dlclose(halHandle);
    halHandle = nullptr;
    return 0;
}

int32_t ConnectedNfcTagVendorAdapter::RegisterCallBack(NfcTagChipEventCallbackT *callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infHandle.registerCallBack == nullptr) {
        HDF_LOGE("%{public}s: registerCallBack NULL", __func__);
        return -1;
    }

    if (callback == nullptr) {
        HDF_LOGE("%{public}s: callback NULL");
        return -1;
    }

    return infHandle.registerCallBack(callback);
}

int32_t ConnectedNfcTagVendorAdapter::WriteNdefData(const std::vector<uint8_t>& ndefData)
{
    if (ndefData.empty()) {
        HDF_LOGE("%{public}s: ndefData empty", __func__);
        return -1;
    }
    if (ndefData.size() > MAX_NDEF_LEN) {
        HDF_LOGE("%{public}s: ndefData size exceeds MAX_NDEF_LEN", __func__);
        return -1;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (infHandle.writeNdefData == nullptr) {
        HDF_LOGE("%{public}s: writeNdefData NULL", __func__);
        return -1;
    }

    return infHandle.writeNdefData(ndefData.data(), ndefData.size());
}

int32_t ConnectedNfcTagVendorAdapter::ReadNdefData(std::vector<uint8_t>& ndefData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infHandle.readNdefData == nullptr) {
        HDF_LOGE("%{public}s: readNdefData NULL", __func__);
        return -1;
    }

    std::vector<uint8_t> buff(MAX_NDEF_LEN);
    uint32_t buffLen = buff.size();
    int32_t ret = infHandle.readNdefData(buff.data(), &buffLen);
    if (ret != 0) {
        HDF_LOGE("%{public}s: readNdefData Fail", __func__);
        return -1;
    }

    if (buffLen > buff.size()) {
        HDF_LOGE("%{public}s: buffLen exceeds buffer size", __func__);
        return -1;
    }
    
    ndefData.assign(buff.begin(), buff.begin() + buffLen);
    return 0;
}

} // ConnectedNfcTag
} // HDI
} // OHOS
