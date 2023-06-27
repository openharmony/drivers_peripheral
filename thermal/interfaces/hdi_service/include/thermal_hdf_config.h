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

#ifndef THERMAL_HDF_CONFIG_H
#define THERMAL_HDF_CONFIG_H

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <libxml/xpath.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#include "base_info_config.h"
#include "sensor_info_config.h"
#include "isolate_info_config.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
struct XMLThermal {
    std::string version;
    std::string product;
};

struct DfxTraceInfo {
    std::string title;
    std::string valuePath;
};

struct XmlTraceConfig {
    std::string outPath;
};

class ThermalHdfConfig {
public:
    using GroupMap = std::map<std::string, std::shared_ptr<SensorInfoConfig>>;
    using PollingMap = std::map<std::string, GroupMap>;
    ThermalHdfConfig() {};
    ~ThermalHdfConfig() = default;
    ThermalHdfConfig(const ThermalHdfConfig&) = delete;
    ThermalHdfConfig& operator=(const ThermalHdfConfig&) = delete;
    static ThermalHdfConfig& GetInstance();

    int32_t ThermalHDIConfigInit(const std::string& path);
    int32_t ParseThermalHdiXMLConfig(const std::string& path);
    void ParseBaseNode(xmlNodePtr node);
    void ParsePollingNode(xmlNodePtr node);
    void ParsePollingSubNode(xmlNodePtr node, XMLThermalNodeInfo& tn);
    void ParseTracingNode(xmlNodePtr node);
    void ParseTracingSubNode(xmlNodePtr node);
    void ParseConfigInfo(const xmlNode* cur, std::vector<XMLThermalZoneInfo>& tzInfoList,
        std::vector<XMLThermalNodeInfo>& tnInfoList);
    std::string GetXmlNodeName(xmlNodePtr node, std::string &defaultName);
    void GetThermalZoneNodeInfo(XMLThermalZoneInfo& tz, const xmlNode* node);
    std::shared_ptr<BaseInfoConfig> GetBaseConfig()
    {
        return baseConfig_;
    }
    std::vector<DfxTraceInfo>& GetTracingInfo()
    {
        return traceInfo_;
    }
    XmlTraceConfig& GetXmlTraceConfig()
    {
        return traceConfig_;
    }
    PollingMap& GetPollingConfig()
    {
        return pollingMap_;
    }

    using IsolateInfoMap = std::map<std::string, std::shared_ptr<IsolateInfoConfig>>;
    void ParseIsolateNode(xmlNodePtr node);
    void ParseIsolateSubNode(xmlNodePtr node, IsolateNodeInfo& tn);
    int32_t GetIsolateCpuNodePath(bool isSim, const std::string &type, std::string &path);
private:
    std::shared_ptr<BaseInfoConfig> baseConfig_;
    PollingMap pollingMap_;
    XMLThermal thermal_;
    XmlTraceConfig traceConfig_;
    std::vector<DfxTraceInfo> traceInfo_;
    IsolateInfoMap isolateInfoMap_;
};
} // V1_1
} // Thermal
} // HDI
} // OHOS

#endif // THERMAL_HDF_CONFIG_H
