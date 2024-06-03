/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "thermal_hdf_config.h"
#include <climits>
#include "thermal_hdf_utils.h"
#include "thermal_log.h"
#include "hdf_remote_service.h"
#include "osal_mem.h"
#include "string_ex.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
const uint32_t DATA_PATH_CHECK = 9;
const int32_t DEFAULT_POLLING_INTERVAL = 30000;
}

ThermalHdfConfig& ThermalHdfConfig::GetInstance()
{
    static ThermalHdfConfig instance;
    return instance;
}

int32_t ThermalHdfConfig::ThermalHDIConfigInit(const std::string& path)
{
    if (!baseConfig_) {
        baseConfig_ = std::make_shared<BaseInfoConfig>();
    }
    return ParseThermalHdiXMLConfig(path);
}

int32_t ThermalHdfConfig::ParseThermalHdiXMLConfig(const std::string& path)
{
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> docPtr(
        xmlReadFile(path.c_str(), nullptr, XML_PARSE_NOBLANKS), xmlFreeDoc);
    if (docPtr == nullptr) {
        THERMAL_HILOGW(COMP_HDI, "failed to read xml file");
        return HDF_ERR_INVALID_OBJECT;
    }

    auto rootNode = xmlDocGetRootElement(docPtr.get());
    if (rootNode == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "failed to read root node");
        return HDF_ERR_INVALID_OBJECT;
    }

    if (!xmlStrcmp(rootNode->name, BAD_CAST"thermal")) {
        xmlChar* xmlVersion = xmlGetProp(rootNode, BAD_CAST"version");
        if (xmlVersion != nullptr) {
            this->thermal_.version = std::string(reinterpret_cast<char*>(xmlVersion));
            xmlFree(xmlVersion);
            THERMAL_HILOGD(COMP_HDI, "version: %{public}s", this->thermal_.version.c_str());
        }

        xmlChar* xmlProduct = xmlGetProp(rootNode, BAD_CAST"product");
        if (xmlProduct != nullptr) {
            this->thermal_.product = std::string(reinterpret_cast<char*>(xmlProduct));
            xmlFree(xmlProduct);
            THERMAL_HILOGD(COMP_HDI, "product: %{public}s", this->thermal_.product.c_str());
        }
    }

    for (auto node = rootNode->children; node; node = node->next) {
        if (node == nullptr) {
            continue;
        }

        if (!xmlStrcmp(node->name, BAD_CAST"base")) {
            ParseBaseNode(node);
        } else if (!xmlStrcmp(node->name, BAD_CAST"polling")) {
            ParsePollingNode(node);
        } else if (!xmlStrcmp(node->name, BAD_CAST"tracing")) {
            ParseTracingNode(node);
        } else if (!xmlStrcmp(node->name, BAD_CAST"isolate")) {
            ParseIsolateNode(node);
        }
    }
    return HDF_SUCCESS;
}

void ThermalHdfConfig::ParseBaseNode(xmlNodePtr node)
{
    auto cur = node->xmlChildrenNode;
    std::vector<BaseItem> vBase;
    while (cur != nullptr) {
        BaseItem item;
        xmlChar* xmlTag = xmlGetProp(cur, BAD_CAST"tag");
        if (xmlTag != nullptr) {
            item.tag = std::string(reinterpret_cast<char*>(xmlTag));
            xmlFree(xmlTag);
            THERMAL_HILOGD(COMP_HDI, "ParseBaseNode tag: %{public}s", item.tag.c_str());
        }

        xmlChar* xmlValue = xmlGetProp(cur, BAD_CAST"value");
        if (xmlValue != nullptr) {
            item.value = std::string(reinterpret_cast<char*>(xmlValue));
            xmlFree(xmlValue);
            THERMAL_HILOGD(COMP_HDI, "ParseBaseNode value: %{public}s", item.value.c_str());
        }

        vBase.push_back(item);
        cur = cur->next;
    }
    baseConfig_->SetBase(vBase);
}

std::string ThermalHdfConfig::GetXmlNodeName(xmlNodePtr node, std::string &defaultName)
{
    std::string name;
    xmlChar* xmlName = xmlGetProp(node, BAD_CAST"name");
    if (xmlName == nullptr) {
        return defaultName;
    }
    name = std::string(reinterpret_cast<char*>(xmlName));
    xmlFree(xmlName);

    return name;
}

void ThermalHdfConfig::ParsePollingNode(xmlNodePtr node)
{
    std::string pollingDefaultName("thermal");
    std::string pollingName = GetXmlNodeName(node, pollingDefaultName);
    GroupMap groupMap;

    auto cur  = node->xmlChildrenNode;
    while (cur != nullptr) {
        std::shared_ptr<SensorInfoConfig> sensorInfo = std::make_shared<SensorInfoConfig>();
        std::string groupDefaultName("actual");
        std::string groupName = GetXmlNodeName(cur, groupDefaultName);
        sensorInfo->SetGroupName(groupName);
        THERMAL_HILOGD(COMP_HDI, "ParsePollingNode groupName: %{public}s", groupName.c_str());

        xmlChar* xmlInterval = xmlGetProp(cur, BAD_CAST"interval");
        if (xmlInterval != nullptr) {
            std::string strInterval = reinterpret_cast<char *>(xmlInterval);
            int32_t interval = DEFAULT_POLLING_INTERVAL;
            StrToInt(TrimStr(strInterval), interval);
            xmlFree(xmlInterval);
            THERMAL_HILOGD(COMP_HDI, "ParsePollingNode interval: %{public}d", interval);
            sensorInfo->SetGroupInterval(interval);
        }

        std::vector<XMLThermalZoneInfo> xmlTzInfoList;
        std::vector<XMLThermalNodeInfo> xmlTnInfoList;
        for (auto subNode = cur->children; subNode; subNode = subNode->next) {
            if (!xmlStrcmp(subNode->name, BAD_CAST"thermal_zone")) {
                XMLThermalZoneInfo tz;
                GetThermalZoneNodeInfo(tz, subNode);
                THERMAL_HILOGI(COMP_HDI, "ParsePollingNode ParsePollingNodetztype: %{public}s, replace: %{public}s",
                    tz.type.c_str(), tz.replace.c_str());
                xmlTzInfoList.push_back(tz);
            } else if (!xmlStrcmp(subNode->name, BAD_CAST"thermal_node")) {
                XMLThermalNodeInfo tn;
                ParsePollingSubNode(subNode, tn);
                THERMAL_HILOGI(COMP_HDI, "ParsePollingNode tntype: %{public}s", tn.type.c_str());
                xmlTnInfoList.push_back(tn);
            }
        }
        sensorInfo->SetXMLThermalZoneInfo(xmlTzInfoList);
        sensorInfo->SetXMLThermalNodeInfo(xmlTnInfoList);
        groupMap.insert(std::make_pair(groupName, sensorInfo));
        cur = cur->next;
    }

    pollingMap_.insert(std::make_pair(pollingName, groupMap));
}

void ThermalHdfConfig::ParsePollingSubNode(xmlNodePtr node, XMLThermalNodeInfo& tn)
{
    DfxTraceInfo info;

    xmlChar* xmlType = xmlGetProp(node, BAD_CAST"type");
    if (xmlType != nullptr) {
        tn.type = std::string(reinterpret_cast<char*>(xmlType));
        xmlFree(xmlType);
    }

    xmlChar* xmlPath = xmlGetProp(node, BAD_CAST"path");
    if (xmlPath != nullptr) {
        tn.path = std::string(reinterpret_cast<char*>(xmlPath));
        xmlFree(xmlPath);
    }
}

void ThermalHdfConfig::ParseTracingNode(xmlNodePtr node)
{
    xmlChar* xmlOutpath = xmlGetProp(node, BAD_CAST"outpath");
    if (xmlOutpath != nullptr) {
        char resolvedPath[PATH_MAX] = {};
        if ((realpath(reinterpret_cast<char *>(xmlOutpath), resolvedPath) != nullptr) &&
            (strncmp(resolvedPath, "/data/log", DATA_PATH_CHECK) == 0)) {
            this->traceConfig_.outPath = std::string(reinterpret_cast<char *>(xmlOutpath));
            xmlFree(xmlOutpath);
        }
    }

    auto cur  = node->xmlChildrenNode;
    while (cur != nullptr) {
        ParseTracingSubNode(cur);
        cur = cur->next;
    }
}

void ThermalHdfConfig::ParseTracingSubNode(xmlNodePtr node)
{
    std::string title;
    DfxTraceInfo info;
    std::string valuePath;

    for (auto subNode = node->children; subNode != nullptr; subNode = subNode->next) {
        if (!xmlStrcmp(subNode->name, BAD_CAST"title")) {
            xmlChar* titlePath = xmlGetProp(subNode, BAD_CAST"path");
            if (titlePath != nullptr) {
                ThermalHdfUtils::ReadNode(
                    std::string(reinterpret_cast<char*>(titlePath)), title);
                xmlFree(titlePath);
            }

            xmlChar* titleName = xmlGetProp(subNode, BAD_CAST"name");
            if (titleName != nullptr) {
                title = std::string(reinterpret_cast<char*>(titleName));
                xmlFree(titleName);
            }
        }

        if (!xmlStrcmp(subNode->name, BAD_CAST"value")) {
            xmlChar* xmlValuePath = xmlGetProp(subNode, BAD_CAST"path");
            if (xmlValuePath != nullptr) {
                valuePath = std::string(reinterpret_cast<char*>(xmlValuePath));
                xmlFree(xmlValuePath);
            }
        }
    }

    info.title = title;
    info.valuePath = valuePath;
    traceInfo_.emplace_back(info);

    for (const auto& item : traceInfo_) {
        THERMAL_HILOGD(COMP_HDI, "item.title = %{public}s", item.title.c_str());
    }
}

void ThermalHdfConfig::GetThermalZoneNodeInfo(XMLThermalZoneInfo& tz, const xmlNode* node)
{
    xmlChar* xmlType = xmlGetProp(node, BAD_CAST"type");
    if (xmlType != nullptr) {
        tz.type = std::string(reinterpret_cast<char*>(xmlType));
        xmlFree(xmlType);
    }

    auto replace = xmlGetProp(node, BAD_CAST("replace"));
    if (replace != nullptr) {
        tz.replace = std::string(reinterpret_cast<char*>(replace));
        tz.isReplace = true;
        xmlFree(replace);
    }
}

void ThermalHdfConfig::ParseIsolateNode(xmlNodePtr node)
{
    THERMAL_HILOGD(COMP_HDI, "in");
    auto cur = node->xmlChildrenNode;
    while (cur != nullptr) {
        std::shared_ptr<IsolateInfoConfig> isolateInfo = std::make_shared<IsolateInfoConfig>();
        std::string groupName;
        xmlChar* xmlName = xmlGetProp(cur, BAD_CAST"name");
        if (xmlName != nullptr) {
            groupName = std::string(reinterpret_cast<char*>(xmlName));
            xmlFree(xmlName);
            isolateInfo->SetGroupName(groupName);
            THERMAL_HILOGD(COMP_HDI, "groupName: %{public}s", groupName.c_str());
        }

        std::vector<IsolateNodeInfo> xmlTnInfoList;
        for (auto subNode = cur->children; subNode; subNode = subNode->next) {
            if (!xmlStrcmp(subNode->name, BAD_CAST"thermal_node")) {
                IsolateNodeInfo tn;
                ParseIsolateSubNode(subNode, tn);
                xmlTnInfoList.push_back(tn);
            }
        }
        isolateInfo->SetIsolateNodeInfo(xmlTnInfoList);
        isolateInfoMap_.insert(std::make_pair(groupName, isolateInfo));
        cur = cur->next;
    }
}

void ThermalHdfConfig::ParseIsolateSubNode(xmlNodePtr node, IsolateNodeInfo& tn)
{
    xmlChar* xmlType = xmlGetProp(node, BAD_CAST"type");
    if (xmlType != nullptr) {
        tn.type = std::string(reinterpret_cast<char*>(xmlType));
        THERMAL_HILOGD(COMP_HDI, "type: %{public}s", tn.type.c_str());
        xmlFree(xmlType);
    }

    xmlChar* xmlPath = xmlGetProp(node, BAD_CAST"path");
    if (xmlPath != nullptr) {
        tn.path = std::string(reinterpret_cast<char*>(xmlPath));
        THERMAL_HILOGD(COMP_HDI, "path: %{public}s", tn.path.c_str());
        xmlFree(xmlPath);
    }
}

int32_t ThermalHdfConfig::GetIsolateCpuNodePath(bool isSim, const std::string &type, std::string &path)
{
    std::string groupName = isSim ? "sim" : "actual";
    THERMAL_HILOGI(COMP_HDI, "isSim %d, type %{public}s, groupName %{public}s", isSim, type.c_str(), groupName.c_str());

    auto mapIter = isolateInfoMap_.find(groupName);
    if (mapIter == isolateInfoMap_.end()) {
        THERMAL_HILOGE(COMP_HDI, "failed to get group %s config", groupName.c_str());
        return HDF_FAILURE;
    }

    std::vector<IsolateNodeInfo> nodeVector = mapIter->second->GetIsolateNodeInfo();
    for (auto nodeIter : nodeVector) {
        if (type == nodeIter.type) {
            path = nodeIter.path;
            THERMAL_HILOGI(COMP_HDI, "path %{public}s", path.c_str());
            return HDF_SUCCESS;
        }
    }

    THERMAL_HILOGE(COMP_HDI, "failed to get type %{public}s path", type.c_str());
    return HDF_FAILURE;
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
