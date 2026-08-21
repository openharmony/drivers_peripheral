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
#include "cJSON.h"
#include "config_policy_utils.h"
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
namespace Serial {
namespace V1_0 {
static constexpr int32_t MAX_SERIALS_NUMBER = 128;
static const char* HOST_CONFIG_PATH = HDF_CONFIG_DIR "/hdf_default.hcb";
static const char* HOST_CHIP_PROD_CONFIG_PATH = HDF_CHIP_PROD_CONFIG_DIR "/hdf_default.hcb";

const struct DeviceResourceNode *HdfGetHcsRootNode()
{
    static const char* adapterConfigPath[] = {
        HOST_CHIP_PROD_CONFIG_PATH,
        HOST_CONFIG_PATH,
    };

    size_t pathNum = sizeof(adapterConfigPath) / sizeof(adapterConfigPath[0]);
    for (size_t i = 0; i < pathNum; ++i) {
        if (access(adapterConfigPath[i], F_OK | R_OK) == 0) {
            SetHcsBlobPath(adapterConfigPath[i]);
            const struct DeviceResourceNode *mgrRoot = HcsGetRootNode();
            return mgrRoot;
        }
        HDF_LOGD("invalid config file path or permission:%{public}s", adapterConfigPath[i]);
    }
    HDF_LOGW("no hcb file found!");
    return nullptr;
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

static constexpr const char* PCIE_SERIAL_CONFIG_PATH = "etc/serial/pcie_serial_config.json";

static std::string ReadFileContent(const std::string& path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (fp == nullptr) {
        HDF_LOGW("%{public}s: cannot open %{public}s, errno=%{public}d", __func__, path.c_str(), errno);
        return "";
    }

    std::string content;
    char buffer[256] = {0};
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        content += buffer;
    }
    (void)fclose(fp);
    return content;
}

static int32_t ParsePcieSerialConfig(const std::string& jsonStr, std::map<std::string, int32_t>& prefixOffsets)
{
    cJSON* root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        HDF_LOGE("%{public}s: cJSON_Parse failed", __func__);
        return HDF_FAILURE;
    }

    cJSON* ports = cJSON_GetObjectItem(root, "pcieSerialPorts");
    if (ports == nullptr || !cJSON_IsArray(ports)) {
        HDF_LOGE("%{public}s: pcieSerialPorts not found or not array", __func__);
        cJSON_Delete(root);
        return HDF_FAILURE;
    }

    int arraySize = cJSON_GetArraySize(ports);
    if (arraySize <= 0 || arraySize > MAX_SERIALS_NUMBER) {
        HDF_LOGE("%{public}s: invalid pcieSerialPorts size=%{public}d", __func__, arraySize);
        cJSON_Delete(root);
        return HDF_FAILURE;
    }

    for (int i = 0; i < arraySize; i++) {
        cJSON* item = cJSON_GetArrayItem(ports, i);
        if (item == nullptr) {
            continue;
        }
        cJSON* prefixItem = cJSON_GetObjectItem(item, "prefix");
        cJSON* offsetItem = cJSON_GetObjectItem(item, "portIdOffset");
        if (prefixItem == nullptr || offsetItem == nullptr || !cJSON_IsString(prefixItem) ||
            !cJSON_IsNumber(offsetItem)) {
            HDF_LOGW("%{public}s: invalid entry at index %{public}d, skipping", __func__, i);
            continue;
        }
        char* prefixStr = prefixItem->valuestring;
        int offsetVal = offsetItem->valueint;
        if (prefixStr == nullptr || strlen(prefixStr) == 0) {
            HDF_LOGW("%{public}s: empty prefix at index %{public}d, skipping", __func__, i);
            continue;
        }
        prefixOffsets[std::string(prefixStr)] = static_cast<int32_t>(offsetVal);
    }

    cJSON_Delete(root);
    return HDF_SUCCESS;
}

int32_t GetPcieSerialConfigs(std::map<std::string, int32_t>& prefixOffsets)
{
    char buf[MAX_PATH_LEN] = {0};
    char* path = GetOneCfgFile(PCIE_SERIAL_CONFIG_PATH, buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        HDF_LOGE("%{public}s: GetOneCfgFile failed for %{public}s", __func__, PCIE_SERIAL_CONFIG_PATH);
        return HDF_FAILURE;
    }

    std::string content = ReadFileContent(path);
    if (content.empty()) {
        HDF_LOGE("%{public}s: failed to read pcie serial config from %{public}s", __func__, path);
        return HDF_FAILURE;
    }

    int32_t ret = ParsePcieSerialConfig(content, prefixOffsets);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to parse pcie serial config from %{public}s", __func__, path);
        return ret;
    }

    HDF_LOGI("%{public}s: loaded %{public}zu pcie serial port configs from %{public}s",
        __func__, prefixOffsets.size(), path);
    return HDF_SUCCESS;
}

} // V1_0
} // Serial
} // HDI
} // OHOS
