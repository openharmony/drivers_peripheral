/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include <securec.h>
#include "codec_hcb_util.h"
#include "hdf_log.h"

#ifdef __OHOS_STANDARD_SYS__
#define HOST_CONFIG_PATH HDF_CONFIG_DIR
#define HOST_CHIP_PROD_CONFIG_PATH HDF_CHIP_PROD_CONFIG_DIR
#else
#define HOST_CONFIG_PATH "/system/etc/hdfconfig"
#endif
#define PRODUCT_PROPERTY "ro.build.product"
#define PRODUCT_NAME_MAX 128

static bool GetConfigFilePath(const char *productName, char *configPath, size_t configPathLen)
{
    static const char *adapterConfigPath[] = {
        HOST_CONFIG_PATH,
        HOST_CHIP_PROD_CONFIG_PATH,
    };

    size_t pathNum = sizeof(adapterConfigPath) / sizeof(adapterConfigPath[0]);
    for (size_t i = 0; i < pathNum; ++i) {
        if (sprintf_s(configPath, configPathLen - 1, "%s/hdf_%s.hcb", adapterConfigPath[i], productName) < 0) {
            HDF_LOGE("failed to generate file path");
            continue;
        }

        if (access(configPath, F_OK | R_OK) == 0) {
            return true;
        }
        HDF_LOGD("invalid config file path or permission:%{public}s", configPath);
    }
    return false;
}

const struct DeviceResourceNode *HdfGetHcsRootNode(void)
{
    char productName[PRODUCT_NAME_MAX] = { 0 };
    char configPath[PATH_MAX] = { 0 };

    int ret = strcpy_s(productName, PRODUCT_NAME_MAX, "default");
    if (ret != HDF_SUCCESS) {
        return NULL;
    }

    if (!GetConfigFilePath(productName, configPath, PATH_MAX)) {
        HDF_LOGE("failed to get config file path");
        return NULL;
    }

    SetHcsBlobPath(configPath);
    const struct DeviceResourceNode *mgrRoot = HcsGetRootNode();
    return mgrRoot;
}
