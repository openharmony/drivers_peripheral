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

#include "thermal_hdf_config.h"

#include "thermal_log.h"
#include "hdf_remote_service.h"
#include "osal/osal_mem.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
ThermalHdfConfig& ThermalHdfConfig::GetInsance()
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

ThermalHdfConfig::ThermalTypeMap ThermalHdfConfig::GetSensorTypeMap()
{
    return typesMap_;
}

int32_t ThermalHdfConfig::ParseThermalHdiXMLConfig(const std::string& path)
{
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> docPtr(
        xmlReadFile(path.c_str(), nullptr, XML_PARSE_NOBLANKS), xmlFreeDoc);
    if (docPtr == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "failed to read xml file");
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
            this->thermal_.version = std::stof(std::string(reinterpret_cast<char*>(xmlVersion)));
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

void ThermalHdfConfig::ParsePollingNode(xmlNodePtr node)
{
    auto cur  = node->xmlChildrenNode;
    while (cur != nullptr) {
        std::shared_ptr<SensorInfoConfig> sensorInfo = std::make_shared<SensorInfoConfig>();
        std::string groupName;
        xmlChar* xmlName = xmlGetProp(cur, BAD_CAST"name");
        if (xmlName != nullptr) {
            groupName = std::string(reinterpret_cast<char*>(xmlName));
            xmlFree(xmlName);
            sensorInfo->SetGroupName(groupName);
            THERMAL_HILOGD(COMP_HDI, "ParsePollingNode groupName: %{public}s", groupName.c_str());
        }

        xmlChar* xmlInterval = xmlGetProp(cur, BAD_CAST"interval");
        if (xmlInterval != nullptr) {
            uint32_t interval = atoi(reinterpret_cast<char*>(xmlInterval));
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
        typesMap_.insert(std::make_pair(groupName, sensorInfo));
        cur = cur->next;
    }
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
    xmlChar* xmlInterval = xmlGetProp(node, BAD_CAST"interval");
    if (xmlInterval != nullptr) {
        this->trace_.interval = std::string(reinterpret_cast<char *>(xmlInterval));
        xmlFree(xmlInterval);
        THERMAL_HILOGD(COMP_HDI, "interval: %{public}s", this->trace_.interval.c_str());
    }

    xmlChar* xmlOutpath = xmlGetProp(node, BAD_CAST"outpath");
    if (xmlOutpath != nullptr) {
        this->trace_.outpath = std::string(reinterpret_cast<char *>(xmlOutpath));
        xmlFree(xmlOutpath);
    }

    auto cur  = node->xmlChildrenNode;
    while (cur != nullptr) {
        ParseTracingSubNode(cur);
        cur = cur->next;
    }
}

void ThermalHdfConfig::ParseTracingSubNode(xmlNodePtr node)
{
    std::string namePath;
    DfxTraceInfo info;
    std::string valuePath;

    for (auto subNode = node->children; subNode != nullptr; subNode = subNode->next) {
        if (!xmlStrcmp(subNode->name, BAD_CAST"title")) {
            xmlChar* titlePath = xmlGetProp(subNode, BAD_CAST"path");
            if (titlePath != nullptr) {
                namePath = std::string(reinterpret_cast<char*>(titlePath));
                xmlFree(titlePath);
            }

            xmlChar* titleName = xmlGetProp(subNode, BAD_CAST"name");
            if (titleName != nullptr) {
                namePath = std::string(reinterpret_cast<char*>(titleName));
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

    info.title = namePath;
    info.value = valuePath;
    traceInfo_.emplace_back(info);

    for (const auto& item : traceInfo_) {
        THERMAL_HILOGD(COMP_HDI, "item.title = %{public}s, item.value = %{public}s",
            item.title.c_str(), item.value.c_str());
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
} // V1_0
} // Thermal
} // HDI
} // OHOS
