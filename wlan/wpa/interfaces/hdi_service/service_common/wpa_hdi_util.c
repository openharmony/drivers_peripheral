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

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <hdf_log.h>
#include <stdlib.h>
#include <limits.h>
#include <regex.h>
#include "securec.h"
#include "wpa_hdi_util.h"

#define MAC_UINT_SIZE 6
#define MAC_STRING_SIZE 17

int ConvertMacToStr(const unsigned char *mac, int macSize, char *macStr, int strLen)
{
    if (mac == NULL || macStr == NULL || macSize != MAC_UINT_SIZE || strLen <= MAC_STRING_SIZE) {
        return -1;
    }
    const int posZero = 0;
    const int posOne = 1;
    const int posTwo = 2;
    const int posThree = 3;
    const int posFour = 4;
    const int posFive = 5;
    if (snprintf_s(macStr, strLen, strLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x", mac[posZero], mac[posOne], mac[posTwo],
        mac[posThree], mac[posFour], mac[posFive]) < 0) {
        return -1;
    }
    return 0;
}

char IsValidHexCharAndConvert(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + ('9' - '0' + 1);
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + ('9' - '0' + 1);
    }
    return -1;
}

int ConvertMacToArray(const char *macStr, unsigned char *mac, int macSize)
{
    if (macStr == NULL || mac == NULL || macSize != MAC_UINT_SIZE || strlen(macStr) != MAC_STRING_SIZE) {
        return -1;
    }
    const int shiftNum = 4;
    const int macSpaceNum = 3;
    unsigned char tmp = 0;
    for (int i = 0, j = 0; i < MAC_STRING_SIZE; ++i) {
        if (j == 0 || j == 1) {
            int8_t v = IsValidHexCharAndConvert(macStr[i]);
            if (v < 0) {
                return -1;
            }
            tmp <<= shiftNum;
            tmp |= v;
            ++j;
        } else {
            if (macStr[i] != ':') {
                return -1;
            }
            mac[i / macSpaceNum] = tmp;
            j = 0;
            tmp = 0;
        }
    }
    mac[MAC_STRING_SIZE / macSpaceNum] = tmp;
    return 0;
}

int CheckMacIsValid(const char *macStr)
{
    if (macStr == NULL || strlen(macStr) != MAC_STRING_SIZE) {
        return -1;
    }
    for (int i = 0, j = 0; i < MAC_STRING_SIZE; ++i) {
        if (j == 0 || j == 1) {
            int v = IsValidHexCharAndConvert(macStr[i]);
            if (v < 0) {
                return -1;
            }
            ++j;
        } else {
            if (macStr[i] != ':') {
                return -1;
            }
            j = 0;
        }
    }
    return 0;
}

int GetIfaceState(const char *ifaceName)
{
    int state = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        HDF_LOGE("GetIfaceState: create socket fail");
        return state;
    }

    struct ifreq ifr;
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    if (strcpy_s(ifr.ifr_name, IFNAMSIZ, ifaceName) != EOK) {
        HDF_LOGE("GetIfaceState: strcpy_s fail");
        close(sock);
        return state;
    }
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        HDF_LOGE("GetIfaceState: can not get interface state: %{public}s", ifaceName);
        close(sock);
        return state;
    }
    state = ((ifr.ifr_flags & IFF_UP) > 0 ? 1 : 0);
    HDF_LOGD("GetIfaceState: current interface state: %{public}d", state);
    close(sock);
    return state;
}

static int CharReplace(char* data, int start, int end, const char hiddenChar)
{
    if (!data) {
        HDF_LOGE("CharReplace: data invalid.");
        return 1;
    }
    for (int i = start; i < end; i++) {
        data[i] = hiddenChar;
    }
    
    return 0;
}

int DataAnonymize(const char *input, int inputLen, char* output, int outputSize)
{
    if (!input || !output || inputLen > outputSize) {
        HDF_LOGE("DataAnonymize: arg invalid.");
        return 1;
    }

    if (memcpy_s(output, outputSize, input, inputLen) != EOK) {
        HDF_LOGE("DataAnonymize: memcpy_s fail");
        return 1;
    }

    const char hiddenChar = '*';
    const int minHiddenSize = 3;
    const int headKeepSize = 3;
    const int tailKeepSize = 3;

    if (inputLen < minHiddenSize) {
        return CharReplace(output, 0, inputLen, hiddenChar);
    }

    if (inputLen < (minHiddenSize + headKeepSize + tailKeepSize)) {
        int beginIndex = 1;
        int hiddenSize = inputLen - minHiddenSize + 1;
        hiddenSize = hiddenSize > minHiddenSize ? minHiddenSize : hiddenSize;
        return CharReplace(output, beginIndex,  beginIndex + hiddenSize, hiddenChar);
    }
    return CharReplace(output, headKeepSize, inputLen - tailKeepSize, hiddenChar);
}

unsigned int AtoiToStrtolUint(const char *input)
{
    if (input == NULL || input[0] == '\0' || strlen(input) > MAX_UINT32_LENGTH) {
        HDF_LOGE("AtoiToStrtolUint: invalid data!");
        return 0;
    }
    char *endPtr = NULL;
    unsigned long result = 0;
    result = strtol(input, &endPtr, NUMBER_BASE);

    if (endPtr == input || *endPtr != '\0') {
        HDF_LOGE("AtoiToStrtolUint: invalid data!");
        return 0;
    } else if (errno == ERANGE) {
        HDF_LOGE("AtoiToStrtolUint: failed!");
        return 0;
    } else {
        return (unsigned int)result;
    }
}

int AtoiToStrtol(const char *input)
{
    if (input == NULL || input[0] == '\0' || strlen(input) > MAX_INT32_LENGTH) {
        HDF_LOGE("AtoiToStrtol: invalid data!");
        return 0;
    }
    char *endPtr = NULL;
    long result = 0;
    result = strtol(input, &endPtr, NUMBER_BASE);

    if (endPtr == input || *endPtr != '\0') {
        HDF_LOGE("AtoiToStrtol: invalid data!");
        return 0;
    } else if (errno == ERANGE) {
        HDF_LOGE("AtoiToStrtol: failed!");
        return 0;
    } else {
        return (int)result;
    }
}

