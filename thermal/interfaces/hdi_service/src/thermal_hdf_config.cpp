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
        this->thermal_.version = std::stof((char*)xmlGetProp(rootNode, BAD_CAST"version"));
        this->thermal_.product = (char*)xmlGetProp(rootNode, BAD_CAST"product");
        THERMAL_HILOGI(COMP_HDI, "version: %{public}s, product: %{public}s",
            this->thermal_.version.c_str(), this->thermal_.product.c_str());
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
            this->trace_.interval = (char*)xmlGetProp(node, BAD_CAST"interval");
            this->trace_.record = (char*)xmlGetProp(node, BAD_CAST"record");
            this->trace_.outpath = (char*)xmlGetProp(node, BAD_CAST"outpath");
            THERMAL_HILOGI(COMP_HDI, "interval: %{public}s, record: %{public}s, outpath: %{private}s",
                this->trace_.interval.c_str(), this->trace_.record.c_str(), this->trace_.outpath.c_str());
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
        item.tag = (char*)xmlGetProp(cur, BAD_CAST"tag");
        item.value = (char*)xmlGetProp(cur, BAD_CAST"value");
        THERMAL_HILOGI(COMP_HDI, "ParseBaseNode tag: %{public}s, value: %{public}s",
            item.tag.c_str(), item.value.c_str());
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
        std::string groupName = (char*)xmlGetProp(cur, BAD_CAST"name");
        sensorInfo->SetGroupName(groupName);
        uint32_t interval = atoi((char*)xmlGetProp(cur, BAD_CAST"interval"));
        THERMAL_HILOGI(COMP_HDI, "ParsePollingNode groupName: %{public}s, interval: %{public}d",
            groupName.c_str(), interval);
        sensorInfo->SetGroupInterval(interval);
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
                tn.type = (char*)xmlGetProp(subNode, BAD_CAST"type");
                tn.path = (char*)xmlGetProp(subNode, BAD_CAST"path");
                SaveThermalDfxTraceInfo(subNode, tn);

                THERMAL_HILOGI(COMP_HDI, "ParsePollingNode tntype: %{public}s, path: %{private}s",
                    tn.type.c_str(), tn.path.c_str());
                xmlTnInfoList.push_back(tn);
            }
        }
        sensorInfo->SetXMLThermalZoneInfo(xmlTzInfoList);
        sensorInfo->SetXMLThermalNodeInfo(xmlTnInfoList);
        typesMap_.insert(std::make_pair(groupName, sensorInfo));
        cur = cur->next;
    }
}

void ThermalHdfConfig::SaveThermalDfxTraceInfo(xmlNodePtr node, XMLThermalNodeInfo tn)
{
    std::string rec;
    DfxTraceInfo info;

    xmlChar* isRecord = xmlGetProp(node, BAD_CAST"record");
    if (isRecord != nullptr) {
        rec = (char*)isRecord;
        THERMAL_HILOGI(COMP_HDI, "ParsePollingNode isRecord: %{public}s", rec.c_str());
        xmlFree(isRecord);
    }

    if (rec == "true") {
        THERMAL_HILOGI(COMP_HDI, "record is true");
        info.title = tn.type;
        info.value = tn.path;
        info.width = "0";
        traceInfo_.emplace_back(info);
    }
}

void ThermalHdfConfig::ParseTracingNode(xmlNodePtr node)
{
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
        if (subNode == nullptr) continue;
        if (!xmlStrcmp(subNode->name, BAD_CAST"title")) {
            xmlChar* titlePath = xmlGetProp(subNode, BAD_CAST"path");
            if (titlePath != nullptr) {
                namePath = (char*)titlePath;
                THERMAL_HILOGD(COMP_HDI, "namePath in path: %{private}s", namePath.c_str());
                xmlFree(titlePath);
            }

            xmlChar* titleName = xmlGetProp(subNode, BAD_CAST"name");
            if (titleName != nullptr) {
                namePath = (char*)titleName;
                THERMAL_HILOGD(COMP_HDI, "namePath in name: %{private}s", namePath.c_str());
                xmlFree(titleName);
            }
        }

        if (!xmlStrcmp(subNode->name, BAD_CAST"value")) {
            valuePath = (char*)xmlGetProp(subNode, BAD_CAST"path");
        }

        if (!xmlStrcmp(subNode->name, BAD_CAST"width")) {
            info.width = (char*)xmlGetProp(subNode, BAD_CAST"value");
        }
    }

    info.title = namePath;
    info.value = valuePath;
    traceInfo_.emplace_back(info);

    for (auto info : traceInfo_) {
        THERMAL_HILOGD(COMP_HDI, "info.title = %{public}s, info.value = %{public}s, info.width = %{public}s",
            info.title.c_str(), info.value.c_str(), info.width.c_str());
    }
}

void ThermalHdfConfig::GetThermalZoneNodeInfo(XMLThermalZoneInfo& tz, const xmlNode* node)
{
    tz.type = (char*)xmlGetProp(node, BAD_CAST"type");
    auto replace = xmlGetProp(node, BAD_CAST("replace"));
    if (replace != nullptr) {
        tz.replace = (char*)replace;
        tz.isReplace = true;
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
