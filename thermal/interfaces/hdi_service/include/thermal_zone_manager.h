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

#ifndef THERMAL_ZONE_MANAGER_H
#define THERMAL_ZONE_MANAGER_H

#include <list>
#include <map>
#include <string>
#include <mutex>
#include "thermal_hdf_config.h"
#include "v1_1/thermal_types.h"
#include "v1_1/ithermal_callback.h"
#include "v1_1/ifan_callback.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
struct ThermalZoneSysfsPathInfo {
    char* name;
    char temperturePath[PATH_MAX];
    char typePath[PATH_MAX];
    int32_t fd;
};

struct ThermalSysfsPathInfo {
    char* name;
    char thermalZonePath[PATH_MAX];
    char coolingDevicePath[PATH_MAX];
    int32_t fd;
};

class ThermalZoneManager {
public:
    ThermalZoneManager() = default;
    ~ThermalZoneManager() = default;

    ThermalZoneSysfsPathInfo GetTzPathInfo()
    {
        return tzSysPathInfo_;
    };

    void SetTzPathInfo(ThermalZoneSysfsPathInfo tzSysPathInfo)
    {
        tzSysPathInfo_ = tzSysPathInfo;
    }

    std::list<ThermalZoneSysfsPathInfo> GetLTZPathInfo()
    {
        return lTzSysPathInfo_;
    }

    std::vector<ThermalZoneInfo> GetlTzInfo()
    {
        return tzInfoList_;
    }

    int32_t ConvertInt(const std::string &value)
    {
        return std::stoi(value.c_str());
    }

    void SetThermalEventCb(const sptr<IThermalCallback> &thermalCb)
    {
        thermalCb_ = thermalCb;
    }

    const sptr<IThermalCallback>& GetThermalEventCb()
    {
        return thermalCb_;
    }

    void DelThermalEventCb()
    {
        thermalCb_ = nullptr;
    }

    void SetFanEventCb(const sptr<IFanCallback> &fanCb)
    {
        fanCb_ = fanCb;
    }

    const sptr<IFanCallback>& GetFanEventCb()
    {
        return fanCb_;
    }

    void DelFanEventCb()
    {
        fanCb_ = nullptr;
    }

    int32_t GetMaxReportTime()
    {
        return maxReportTime_;
    }

    int32_t GetMaxCd()
    {
        return maxCd_;
    }

    void Init();
    int32_t UpdateThermalZoneData();
    void CalculateMaxCd();
    void ReportThermalZoneData(int32_t reportTime);
    HdfThermalCallbackInfo GetCallbackInfo();
    void DumpPollingInfo();

private:
    void InitThermalZoneSysfs();
    void CallbackOnEvent(std::string name, HdfThermalCallbackInfo &info);
    void CollectCallbackInfo(
        HdfThermalCallbackInfo &callbackInfo, const std::shared_ptr<SensorInfoConfig> &sensorInfo, int32_t reportTime);
    void UpdateDataType(XMLThermalZoneInfo& tzIter, ReportedThermalData& data, int32_t tzn);
    void UpdateThermalZoneInfo(std::shared_ptr<SensorInfoConfig> infoConfig);
    int32_t GetMaxCommonDivisor(int32_t a, int32_t b);
    int32_t GetIntervalCommonDivisor(std::vector<int32_t> intervalList);
    struct ThermalZoneSysfsPathInfo tzSysPathInfo_;
    std::list<ThermalZoneSysfsPathInfo> lTzSysPathInfo_;
    std::vector<ThermalZoneInfo> tzInfoList_;
    ThermalHdfConfig::PollingMap pollingMap_;
    sptr<IThermalCallback> thermalCb_;
    sptr<IFanCallback> fanCb_;
    int32_t maxCd_;
    int32_t maxReportTime_;
    std::map<std::string, int32_t> tznMap_;
    std::mutex mutex_;
};
} // V1_1
} // Thermal
} // HDI
} // OHOS
#endif // THERMAL_ZONE_MANAGER_H
