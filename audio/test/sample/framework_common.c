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

#include "framework_common.h"
#include <string.h>
#include "securec.h"
#include "hdf_base.h"

#define MOVE_LEFT_NUM 8
#define UHDF_PASSTHROUGH_LIB "libhdi_audio"
#define UHDF_CLIENT_LIB      "libhdi_audio_client"

void SystemInputFail(void)
{
    printf("please ENTER to go on...\n");
    while (getchar() != '\n') {
        continue;
    }
}

uint32_t StringToInt(const char *flag)
{
    if (flag == NULL) {
        return 0;
    }
    uint32_t temp = flag[0];
    for (int32_t i = (int32_t)strlen(flag) - 1; i >= 0; i--) {
        temp <<= MOVE_LEFT_NUM;
        temp += flag[i];
    }
    return temp;
}

int32_t CheckPcmFormat(int32_t val, uint32_t *audioPcmFormat)
{
    if (audioPcmFormat == NULL) {
        AUDIO_FUNC_LOGE("fomat is null!");
        return HDF_FAILURE;
    }
    switch (val) {
        case AUDIO_FORMAT_PCM_8_BIT:
            *audioPcmFormat = AUDIO_FORMAT_PCM_8_BIT;
            break;
        case AUDIO_FORMAT_PCM_16_BIT:
            *audioPcmFormat = AUDIO_FORMAT_PCM_16_BIT;
            break;
        case AUDIO_FORMAT_PCM_24_BIT:
            *audioPcmFormat = AUDIO_FORMAT_PCM_24_BIT;
            break;
        case AUDIO_FORMAT_PCM_32_BIT:
            *audioPcmFormat = AUDIO_FORMAT_PCM_32_BIT;
            break;
        default:
            *audioPcmFormat = AUDIO_FORMAT_PCM_16_BIT;
            break;
    }

    return HDF_SUCCESS;
}

uint32_t PcmFormatToBits(enum AudioFormat formatBit)
{
    switch (formatBit) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return PCM_16_BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return PCM_8_BIT;
        default:
            return PCM_16_BIT;
    }
}

void CleanStdin(void)
{
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

void FileClose(FILE **file)
{
    if ((file != NULL) && ((*file) != NULL)) {
        (void)fclose(*file);
        *file = NULL;
    }
    return;
}

int32_t FormatLoadLibPath(char *resolvedPath, int32_t pathLen, int choice)
{
    if (resolvedPath == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL.");
        return HDF_FAILURE;
    }
    char *uhdfLibPath = NULL;
    switch (choice) {
        case DIRECT: // Direct Loading
            uhdfLibPath = HDF_LIBRARY_FULL_PATH(UHDF_PASSTHROUGH_LIB);
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", uhdfLibPath) < 0) {
                AUDIO_FUNC_LOGE("snprintf_s failed!");
                return HDF_FAILURE;
            }
            break;
        case SERVICE: // IPC Loading
            uhdfLibPath = HDF_LIBRARY_FULL_PATH(UHDF_CLIENT_LIB);
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", uhdfLibPath) < 0) {
                AUDIO_FUNC_LOGE("snprintf_s failed!");
                return HDF_FAILURE;
            }
            break;
        default:
            uhdfLibPath = HDF_LIBRARY_FULL_PATH(UHDF_PASSTHROUGH_LIB);
            printf("Input error,Switched to direct loading in for you,");
            SystemInputFail();
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", uhdfLibPath) < 0) {
                return HDF_FAILURE;
            }
            break;
    }
    return HDF_SUCCESS;
}
