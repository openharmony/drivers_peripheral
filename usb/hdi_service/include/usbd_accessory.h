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

#ifndef OHOS_HDI_USB_V1_1_USBD_ACCESSORY_H
#define OHOS_HDI_USB_V1_1_USBD_ACCESSORY_H

#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <vector>
#include <string>
#include <map>
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_1 {

/* ioctls for retrieving strings set by the host */
#define ACCESSORY_GET_STRING_MANUFACTURER   _IOW('M', 1, char[256])
#define ACCESSORY_GET_STRING_MODEL          _IOW('M', 2, char[256])
#define ACCESSORY_GET_STRING_DESCRIPTION    _IOW('M', 3, char[256])
#define ACCESSORY_GET_STRING_VERSION        _IOW('M', 4, char[256])
#define ACCESSORY_GET_STRING_URI            _IOW('M', 5, char[256])
#define ACCESSORY_GET_STRING_SERIAL         _IOW('M', 6, char[256])
/* returns 1 if there is a start request pending */
#define ACCESSORY_IS_START_REQUESTED        _IO('M', 7)
/* returns audio mode (set via the ACCESSORY_SET_AUDIO_MODE control request) */
#define ACCESSORY_GET_AUDIO_MODE            _IO('M', 8)
#define AOA_IOCTL_EXTRA_DATA                0xC0
#define AOA_GET_EXTRA_DATA                  _IOW('M', AOA_IOCTL_EXTRA_DATA, char[256])


class UsbdAccessory {
public:
    static UsbdAccessory &GetInstance();
    int32_t GetAccessoryInfo(std::vector<std::string> &accessoryInfo);
    int32_t OpenAccessory(int32_t &fd);
    int32_t CloseAccessory(int32_t fd);
    void HandleEvent(int32_t state);
private:
    int32_t GetAccessoryString(int32_t fd, int32_t cmd, std::string &accInfoString);
    int32_t ExtraToString(char* buffer, int32_t len, std::string &extraData);
    void init_base64_char_map();
    std::string base64_encode(char* buffer, int32_t len);
    std::map<char, int> base64_char_map;
    int32_t accFd = {0};
};

} // namespace V1_1
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V1_1_USBD_ACCESSORY_H
