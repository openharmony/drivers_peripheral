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

#ifndef POWER_SUPPLY_PROVIDER_H
#define POWER_SUPPLY_PROVIDER_H

#include <cstdio>
#include <cstring>
#include <climits>
#include <map>
#include <vector>
#include <mutex>
#include "batteryd_api.h"
#include "v2_0/ibattery_interface.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
class PowerSupplyProvider {
public:
    // Keep it same as the BatteryHealthState in battery_info.h
    enum BatteryHealthState {
        BATTERY_HEALTH_UNKNOWN = 0,
        BATTERY_HEALTH_GOOD,
        BATTERY_HEALTH_OVERHEAT,
        BATTERY_HEALTH_OVERVOLTAGE,
        BATTERY_HEALTH_COLD,
        BATTERY_HEALTH_DEAD,
        BATTERY_HEALTH_RESERVED,
    };

    // Keep it same as the BatteryChargeState in battery_info.h
    enum BatteryChargeState {
        CHARGE_STATE_NONE = 0,
        CHARGE_STATE_ENABLE,
        CHARGE_STATE_DISABLE,
        CHARGE_STATE_FULL,
        CHARGE_STATE_RESERVED,
    };

    // Keep it same as the BatteryPluggedType in battery_info.h
    enum BatteryPluggedType {
        PLUGGED_TYPE_NONE = 0,
        PLUGGED_TYPE_AC,
        PLUGGED_TYPE_USB,
        PLUGGED_TYPE_WIRELESS,
        PLUGGED_TYPE_BUTT
    };

    // Keep it same as the ChargeType in charger.h
    enum ChargeType {
        CHARGE_TYPE_NONE = 0,
        CHARGE_TYPE_WIRED_NORMAL,
        CHARGE_TYPE_WIRED_QUICK,
        CHARGE_TYPE_WIRED_SUPER_QUICK,
        CHARGE_TYPE_WIRELESS_NORMAL,
        CHARGE_TYPE_WIRELESS_QUICK,
        CHARGE_TYPE_WIRELESS_SUPER_QUICK
    };

    PowerSupplyProvider();
    virtual ~PowerSupplyProvider();

    int32_t InitPowerSupplySysfs();
    void InitDefaultSysfs();
    void InitChargerSysfs();
    int32_t ParseCapacity(int32_t* capacity);
    int32_t ParseTotalEnergy(int32_t* capacity);
    int32_t ParseCurrentAverage(int32_t* curAverage);
    int32_t ParseCurrentNow(int32_t* curNow);
    int32_t ParseRemainEnergy(int32_t* remainEnergy);
    int32_t ParseVoltage(int32_t* voltage);
    int32_t ParseTemperature(int32_t* temperature);
    int32_t ParseHealthState(int32_t* healthState);
    int32_t ParsePluggedType(int32_t* pluggedType);
    int32_t ParseChargeState(int32_t* chargeState);
    int32_t ParseChargeCounter(int32_t* chargeCounter);
    int32_t ParsePresent(int8_t* present);
    int32_t ParseTechnology(std::string& technology);
    int32_t ParseChargeType(int32_t* chargeType, std::string& chargeTypePath);
    BatterydInfo GetBatteryInfo();
    void ParseUeventToBatterydInfo(const char* msg, struct BatterydInfo* info);
    void UpdateInfoByReadSysFile(struct BatterydInfo* info);
    void SetSysFilePath(const std::string& path);
    void InitBatteryPath();
    int32_t SetChargingLimit(const std::vector<ChargingLimit>& chargingLimit,
        std::string& currentPath, std::string& voltagePath);
    
    int32_t SetConfigByPath(const std::string& path, const std::string& value);
    int32_t GetConfigByPath(const std::string& path, std::string& result);
    int32_t CheckPathExists(const std::string& path, bool& result);

private:
    struct BatterySysfsInfo {
        char* name = nullptr;
        std::string capacityPath;
        std::string voltagePath;
        std::string temperaturePath;
        std::string healthStatePath;
        std::string chargeStatePath;
        std::string presentPath;
        std::string technologyPath;
        std::string chargeCounterPath;
        std::string totalEnergyPath;
        std::string curAveragePath;
        std::string curNowPath;
        std::string remainEnergyPath;
        std::string uevent;
    } batterySysfsInfo_;

    static inline int32_t ParseInt(const char* str);
    static inline void Trim(char* str);
    static inline void CapacityAssigner(const char* str, struct BatterydInfo* info);
    static inline void TotalEnergyAssigner(const char* str, struct BatterydInfo* info);
    static inline void CurrentAverageAssigner(const char* str, struct BatterydInfo* info);
    static inline void CurrentNowAssigner(const char* str, struct BatterydInfo* info);
    static inline void RemainEnergyAssigner(const char* str, struct BatterydInfo* info);
    static inline void VoltageAssigner(const char* str, struct BatterydInfo* info);
    static inline void TemperatureAssigner(const char* str, struct BatterydInfo* info);
    static int32_t HealthStateEnumConverter(const char* str);
    static inline void HealthStateAssigner(const char* str, struct BatterydInfo* info);
    static int32_t ChargeStateEnumConverter(const char* str);
    static inline void ChargeStateAssigner(const char* str, struct BatterydInfo* info);
    static inline void PresentAssigner(const char* str, struct BatterydInfo* info);
    static inline void TechnologyAssigner(const char* str, struct BatterydInfo* info);
    static inline void ChargeCounterAssigner(const char* str, struct BatterydInfo* info);
    static int32_t ChargeTypeEumConverter(const char* str);

    void TraversalNode();
    void CheckSubfolderNode(const std::string& path);
    void FormatPath(std::string& path, size_t size, const char* format, const char* basePath, const char* name) const;
    void FormatSysfsPaths();
    int32_t ReadSysfsFile(const char* path, char* buf, size_t size);
    int32_t ReadBatterySysfsToBuff(const char* path, char* buf, size_t size);
    void GetPluggedTypeName(char* buf, size_t size);
    int32_t PluggedTypeEnumConverter(const char* str) const;
    int32_t ParsePluggedMaxCurrent(int32_t* maxCurrent);
    int32_t ParsePluggedMaxVoltage(int32_t* maxVoltage);
    void CopyBatteryInfo(const struct BatterydInfo* info) const;
    void CreateFile(const std::string& path, const std::string& content);
    void CreateMockTechPath(std::string& mockTechPath);
    void CreateMockChargerPath(std::string& mockChargerPath);
    void CreateMockBatteryPath(std::string& mockBatteryPath);
    void CreateMockChargeTypePath(std::string& mockChargeTypePath);
    int32_t ReadFileToMap(std::map<std::string, std::string>& chargingLimitMap, std::string chargingLimitPath);
    int32_t WriteConf(std::string path);
    std::vector<std::string> nodeNames_;
    std::map<std::string, std::string> nodeNamePathMap_;
    std::map<std::string, int32_t> nodeCacheFiles_;
    std::string path_;
    int32_t index_;
    std::mutex mutex_;
};
}  // namespace V2_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS

#endif // POWER_SUPPLY_PROVIDER_H
