/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "serial_hcb_util.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include "device_resource_if.h"
#include "hcs_tree_if.h"
#include "hdf_base.h"
#include "hdf_cstring.h"
#include "hdf_device_node.h"
#include "hdf_device_object.h"
#include "hdf_core_log.h"
#include "hdf_dlist.h"
#include "hdf_sbuf.h"
#include "hcs_dm_parser.h"

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
static constexpr int32_t MAX_SERIALS_NUMBER = 128;
static const std::string HOST_CONFIG_PATH = HDF_CONFIG_DIR;
static const std::string HOST_CHIP_PROD_CONFIG_PATH = HDF_CHIP_PROD_CONFIG_DIR;
static constexpr int32_t PRODUCT_NAME_MAX = 128;

static bool GetConfigFilePath(std::string& productName, char *configPath, size_t configPathLen)
{
    static const std::string adapterConfigPath[] = {
        HOST_CHIP_PROD_CONFIG_PATH,
        HOST_CONFIG_PATH,
    };

    size_t pathNum = sizeof(adapterConfigPath) / sizeof(adapterConfigPath[0]);
    for (size_t i = 0; i < pathNum; ++i) {
        std::string configPath = adapterConfigPath[i] + "/hdf_" + productName + ".hcb";
        if (access(configPath.c_str(), F_OK | R_OK) == 0) {
            return true;
        }
        HDF_LOGD("invalid config file path or permission:%{public}s", configPath);
    }
    return false;
}

const struct DeviceResourceNode *HdfGetHcsRootNode()
{
    char configPath[PATH_MAX] = { 0 };
    std::string productName = "default";

    if (!GetConfigFilePath(productName, configPath, PATH_MAX)) {
        HDF_LOGE("failed to get config file path");
        return nullptr;
    }

    SetHcsBlobPath(configPath);
    const struct DeviceResourceNode *mgrRoot = HcsGetRootNode();
    return mgrRoot;
}

static int32_t LoadOnboardSerialList(struct DeviceResourceIface *devResInstance,
    const struct DeviceResourceNode *onboardSerialList, std::set<std::string>& serials)
{
    int32_t idTabCount = devResInstance->GetElemNum(onboardSerialList, "OnboardSerialList");
    if (idTabCount <= 0 || idTabCount > MAX_SERIALS_NUMBER) {
        HDF_LOGE("%{public}s: idTableList not found!", __func__);
        return HDF_FAILURE;
    }
    for (int32_t count = 0; count < idTabCount; count++) {
        const char *onboardSerial = nullptr;
        int32_t ret = devResInstance->GetStringArrayElem(
            onboardSerialList, "OnboardSerialList", count, &onboardSerial, nullptr);
        if (ret != HDF_SUCCESS || onboardSerial == nullptr) {
            HDF_LOGE("OnboardSerialList not found!");
            return ret;
        }
        serials.insert(onboardSerial);
    }
    return HDF_SUCCESS;
}

int32_t GetOnboardSerialConfigs(std::set<std::string>& serials)
{
    struct DeviceResourceIface *devResInstance = nullptr;
    const struct DeviceResourceNode *rootNode = nullptr;
    const struct DeviceResourceNode *configNode = nullptr;

    devResInstance = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (devResInstance == nullptr) {
        HDF_LOGE("%s: devResInstance is NULL!", __func__);
        return HDF_FAILURE;
    }

    rootNode = HdfGetHcsRootNode();
    if (rootNode == nullptr) {
        HDF_LOGE("%s: devResNode is NULL!", __func__);
        return HDF_FAILURE;
    }

    configNode = devResInstance->GetNodeByMatchAttr(rootNode, "serial_config_match");
    if (configNode == nullptr) {
        HDF_LOGE("%s: usbPnpNode is NULL!", __func__);
        return HDF_FAILURE;
    }

    return LoadOnboardSerialList(devResInstance, configNode, serials);
}

} // V1_0
} // Serials
} // HDI
} // OHOS
