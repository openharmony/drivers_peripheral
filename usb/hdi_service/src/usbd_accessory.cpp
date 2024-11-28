/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include "usbd_accessory.h"
#include <cerrno>
#include <unistd.h>
#include <securec.h>

#include "hdf_base.h"
#include "hdf_log.h"
#include "usbd_wrapper.h"
#include "usbd_type.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_1 {

const char *ACCESSORY_DRIVER_NAME = "/dev/usb_accessory";
constexpr int BUFFER_SIZE = 256;
static const std::vector<int32_t> accStringList = { ACCESSORY_GET_STRING_MANUFACTURER, ACCESSORY_GET_STRING_MODEL,
                                                    ACCESSORY_GET_STRING_DESCRIPTION, ACCESSORY_GET_STRING_VERSION,
                                                    ACCESSORY_GET_STRING_SERIAL, AOA_GET_EXTRA_DATA };

const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static const int BASE64_BITS_PER_CHAR = -6;
static const uint32_t BASE64_VAL_SHIFT = 8;
static const int BASE64_GROUP_SIZE = 4;
static const int32_t MIN_LENGTH_REQUIRED = 10;
static const uint8_t BASE64_CHAR_MASK3F  = 0x3F;

UsbdAccessory &UsbdAccessory::GetInstance()
{
    static UsbdAccessory instance;
    return instance;
}

void UsbdAccessory::init_base64_char_map()
{
    for (int32_t i = 0; i < base64_chars.size(); ++i) {
        base64_char_map[base64_chars[i]] = i;
    }
}

std::string UsbdAccessory::base64_encode(char *buffer, int32_t len)
{
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: buffer is nullptr", __func__);
        return "";
    }
    std::string encoded_string;
    uint32_t val = 0;
    int valb = BASE64_BITS_PER_CHAR;
    for (int32_t i = 0; i < len; i++) {
        val = (val << BASE64_VAL_SHIFT) + buffer[i];
        valb += BASE64_VAL_SHIFT;
        while (valb >= 0) {
            encoded_string.push_back(base64_chars[(val >> valb) & BASE64_CHAR_MASK3F]);
            valb += BASE64_BITS_PER_CHAR;
        }
    }
    if (valb > BASE64_BITS_PER_CHAR) {
        encoded_string.push_back(base64_chars[((val << BASE64_VAL_SHIFT) >> (valb + BASE64_VAL_SHIFT))
            & BASE64_CHAR_MASK3F]);
    }
    while (encoded_string.size() % BASE64_GROUP_SIZE) {
        encoded_string.push_back('=');
    }
    return encoded_string;
}

int32_t UsbdAccessory::ExtraToString(char* buffer, int32_t len, std::string &extraData)
{
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: buffer is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (len < MIN_LENGTH_REQUIRED) {
        return HDF_FAILURE;
    }
    int16_t actLen = *(buffer + BASE64_VAL_SHIFT);
    actLen = actLen >= len ? len: actLen;
    if (base64_char_map.empty()) {
        init_base64_char_map();
    }
    extraData = base64_encode(buffer, actLen);
    return HDF_SUCCESS;
}

int32_t UsbdAccessory::GetAccessoryString(int32_t fd, int32_t cmd, std::string &accInfoString)
{
    char buffer[BUFFER_SIZE];
    if (memset_s(buffer, BUFFER_SIZE, 0, BUFFER_SIZE) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    int32_t ret = ioctl(fd, cmd, buffer);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d ioctl failed, ret: %{public}d", __func__, __LINE__, ret);
        return ret;
    }
    
    accInfoString = buffer;
    if (cmd == AOA_GET_EXTRA_DATA) {
        return ExtraToString(buffer, ret, accInfoString);
    }
    return HDF_SUCCESS;
}
int32_t UsbdAccessory::GetAccessoryInfo(std::vector<std::string> &accessoryInfo)
{
    int32_t fd = open(ACCESSORY_DRIVER_NAME, O_RDWR);
    if (fd < 0) {
        HDF_LOGE("%{public}s:%{public}d open failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    int32_t ret = HDF_FAILURE;
    std::string accInfoString;
    for (size_t i = 0; i < accStringList.size(); i++) {
        ret = GetAccessoryString(fd, accStringList[i], accInfoString);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d SetAccessoryString failed", __func__, __LINE__);
            continue;
        }
        accessoryInfo.push_back(accInfoString);
    }
    close(fd);
    return HDF_SUCCESS;
}
int32_t UsbdAccessory::OpenAccessory(int32_t &fd)
{
    if (accFd > 0) {
        fd = accFd;
        return HDF_ERR_DEVICE_BUSY;
    }
    accFd = open(ACCESSORY_DRIVER_NAME, O_RDWR);
    if (accFd < 0) {
        HDF_LOGE("%{public}s:%{public}d open failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    fd = accFd;
    return HDF_SUCCESS;
}

int32_t UsbdAccessory::CloseAccessory(int32_t fd)
{
    if (accFd > 0) {
        close(accFd);
    }
    close(fd);
    accFd = 0;
    return HDF_SUCCESS;
}

void UsbdAccessory::HandleEvent(int32_t state)
{
    if (state == ACT_DOWNDEVICE && accFd > 0) {
        close(accFd);
        accFd = 0;
    }
}
}  // namespace V1_1
}  // namespace Usb
}  // namespace HDI
}  // namespace OHOS
