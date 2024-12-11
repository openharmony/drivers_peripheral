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

static const uint32_t BASE64_VAL_SHIFT = 8;
static const int32_t MIN_LENGTH_REQUIRED = 10;
const int INDEX_FIRST = 0;
const int INDEX_SECOND = 1;
const int INDEX_THIRD = 2;
const int INDEX_FORTH = 3;
const int INDEX_FIFTH = 4;
const uint8_t PARAM_FC = 0xfc;
const uint8_t PARAM_03 = 0x03;
const uint8_t PARAM_F0 = 0xf0;
const uint8_t PARAM_0F = 0x0f;
const uint8_t PARAM_C0 = 0xc0;
const uint8_t PARAM_3F = 0x3f;
const uint32_t OFFSET2 = 2;
const uint32_t OFFSET4 = 4;
const uint32_t OFFSET6 = 6;

UsbdAccessory &UsbdAccessory::GetInstance()
{
    static UsbdAccessory instance;
    return instance;
}

void UsbdAccessory::init_base64_char_map()
{
    for (size_t i = 0; i < base64_chars.size(); ++i) {
        base64_char_map[base64_chars[i]] = static_cast<int>(i);
    }
}

std::string UsbdAccessory::base64_encode(char *buffer, int32_t len)
{
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: buffer is nullptr", __func__);
        return "";
    }

    std::string ret;
    uint32_t i = 0;
    uint8_t charArray3[INDEX_FORTH];
    uint8_t charArray4[INDEX_FIFTH];

    while (len > 0) {
        charArray3[i++] = *(buffer++);
        if (i == sizeof(charArray3)) {
            charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
            charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
                                       ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
            charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
                                      ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
            charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
            for (i = 0; i < sizeof(charArray4); i++) {
                ret += base64_chars[charArray4[i]];
            }
            i = 0;
        }
        len--;
    }

    if (i == 0) {
        return ret;
    }

    if (i) {
        uint32_t j = 0;
        for (j = i; j < sizeof(charArray3); j++) {
            charArray3[j] = '\0';
        }
        charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
        charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
                                   ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
        charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
                                  ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
        charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
        for (j = 0; j < i + 1; j++) {
            ret += base64_chars[charArray4[j]];
        }
        while (i < sizeof(charArray3)) {
            ret += '=';
            i++;
        }
    }
    return ret;
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
