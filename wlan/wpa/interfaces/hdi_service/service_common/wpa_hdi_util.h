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

#ifndef WPA_HDI_UTIL_H
#define WPA_HDI_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define NUMBER_BASE 10
#define MAX_INT32_LENGTH 11   /* -2147483648 ~ 2147483647 */
#define MAX_UINT32_LENGTH 10  /* 0 ~ 4294967295 */

/**
 * @Description Convert [a,b,c,d,e,f] mac address to string type [xx:xx:xx:xx:xx:xx]
 *
 * @param mac - mac address
 * @param macSize - mac size, must be equal to 6
 * @param macStr - output mac string, type: [xx:xx:xx:xx:xx:xx]
 * @param strLen - mac string len, must bigger than 17
 * @return int - convert result. 0 - Failed 1 - Success
 */
int ConvertMacToStr(const unsigned char *mac, int macSize, char *macStr, int strLen);

/**
 * @Description Convert mac string type [xx:xx:xx:xx:xx:xx] to array type
 *
 * @param macStr - input mac address, string type like xx:xx:xx:xx:xx:xx
 * @param mac - output mac array
 * @param macSize - mac array length, must be equal to 6
 * @return int - convert result. 0 - Failed 1 - Success
 */
int ConvertMacToArray(const char *macStr, unsigned char *mac, int macSize);

/**
 * @Description Judge input is valid mac string
 *
 * @param macStr - input mac string
 * @return int - -1 - invalid 0 valid
 */
int CheckMacIsValid(const char *macStr);

/**
 * @Description Get the state of interface
 * @param ifaceName - the name of interface
 * @return int - 0: down 1: up
 */
int GetIfaceState(const char *ifaceName);

/**
 * @DataAnonymize Anonymize the input data
 * @param input - the data to anonymize
 * @param inputlen - the length of the input data
 * @param output - anonymized data
 * @param outputSize - the size the output data
 * @return int - 0: success 1: failied
 */
int DataAnonymize(const char *input, int inputLen, char* output, int outputSize);

char IsValidHexCharAndConvert(char c);

unsigned int AtoiToStrtolUint(const char *input);

int AtoiToStrtol(const char *input);

#ifdef __cplusplus
}
#endif
#endif
