# Battery<a name="ZH-CN_TOPIC_0000001124650036"></a>

-   [Introduction](#section11660541593)
-   [Directory](#section161941989596)
    -   [Interface Description](#section1551164914237)
    -   [Usage Instructions](#section129654513264)

-   [Related Repositories](#section1371113476307)

## Introduction<a name="section11660541593"></a>

This repository contains the Battery module HDI (Hardware Driver Interface) definitions and implementations, providing battery management driver capability interfaces for upper-layer system services. The Battery HDI interfaces mainly include:

-   **Battery Info**: Responsible for obtaining various battery information, including capacity, voltage, temperature, health state, charging state, etc.
-   **Battery Config**: Responsible for battery configuration management, supporting getting and setting battery configuration items.
-   **Callback**: Responsible for battery event change callback notifications.

## Directory<a name="section161941989596"></a>

The source code directory structure is as follows:

```
/drivers/peripheral/battery
├── interfaces              # Battery module driver capability interfaces for upper-layer services
│   └── hdi_service        # HDI layer framework code
│       ├── include        # Header files
│       ├── profile        # Configuration files
│       ├── src            # HDI layer source code
│       └── test           # Test code
│           ├── unittest   # Unit tests
│           ├── systemtest # System tests
│           └── fuzztest   # Fuzz tests
└── utils                  # Utility code
```

### Interface Description<a name="section1551164914237"></a>

The Battery driver module provides interfaces to upper-layer system services through the HDI layer, with main functions including: obtaining battery information, setting charging limits, battery configuration management, etc. The provided interfaces are shown in [Table1 Battery HDI Interface List](#table1513255710559):

**Table 1**  Battery HDI Interface List

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" align="center" valign="top" width="12.121212121212123%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>Header File</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="64.95649564956496%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>Interface Name</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="22.922292229222922%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>Function Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row13132357165514"><td class="cellrowborder" rowspan="21" valign="top" width="12.121212121212123%" headers="mcps1.2.4.1.1 "><p id="p829618389386"><a name="p829618389386"></a><a name="p829618389386"></a></p>
<p id="p35261387384"><a name="p35261387384"></a><a name="p35261387384"></a></p>
<p id="p776383812388"><a name="p776383812388"></a><a name="p776383812388"></a></p>
<p id="p11950123812382"><a name="p11950123812382"></a><a name="p11950123812382"></a></p>
<p id="p13168103915381"><a name="p13168103915381"></a><a name="p13168103915381"></a></p>
<p id="p825185015460"><a name="p825185015460"></a><a name="p825185015460"></a>v2_0/ibattery_interface.h</p>
</td>
<td class="cellrowborder" valign="top" width="64.95649564956496%" headers="mcps1.2.4.1.2 "><p id="p1365411515117"><a name="p1365411515117"></a><a name="p1365411515117"></a>int32_t Register(const sptr<IBatteryCallback>& callback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p041814588404"><a name="p041814588404"></a><a name="p041814588404"></a>Register battery callback</p>
</td>
</tr>
<tr id="row9132135715515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1398804043612"><a name="p1398804043612"></a><a name="p1398804043612"></a>int32_t UnRegister();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1341845816404"><a name="p1341845816404"></a><a name="p1341845816404"></a>Unregister battery callback</p>
</td>
</tr>
<tr id="row171330575555"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1974125024812"><a name="p1974125024812"></a><a name="p1974125024812"></a>int32_t ChangePath(const std::string& path);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1041815816403"><a name="p1041815816403"></a><a name="p1041815816403"></a>Change battery path</p>
</td>
</tr>
<tr id="row576145883720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8761658183714"><a name="p8761658183714"></a><a name="p8761658183714"></a>int32_t GetCapacity(int32_t& capacity);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p15418165812409"><a name="p15418165812409"></a><a name="p15418165812409"></a>Get battery capacity</p>
</td>
</tr>
<tr id="row1957862120383"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p55781217381"><a name="p55781217381"></a><a name="p55781217381"></a>int32_t GetTotalEnergy(int32_t& totalEnergy);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1641875834010"><a name="p1641875834010"></a><a name="p1641875834010"></a>Get total battery energy</p>
</td>
</tr>
<tr id="row127635162380"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p3763916143816"><a name="p3763916143816"></a><a name="p3763916143816"></a>int32_t GetCurrentAverage(int32_t& curAverage);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418195874019"><a name="p10418195874019"></a><a name="p10418195874019"></a>Get average current</p>
</td>
</tr>
<tr id="row14230131383819"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1723081310386"><a name="p1723081310386"></a><a name="p1723081310386"></a>int32_t GetCurrentNow(int32_t& curNow);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418658184012"><a name="p10418658184012"></a><a name="p10418658184012"></a>Get instantaneous current</p>
</td>
</tr>
<tr id="row159636983816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p89635916383"><a name="p89635916383"></a><a name="p89635916383"></a>int32_t GetRemainEnergy(int32_t& remainEnergy);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p19418205894012"><a name="p19418205894012"></a><a name="p19418205894012"></a>Get remaining energy</p>
</td>
</tr>
<tr id="row76872047153720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1368818472376"><a name="p1368818472376"></a><a name="p1368818472376"></a>int32_t GetBatteryInfo(BatteryInfo& info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p144182582405"><a name="p144182582405"></a><a name="p144182582405"></a>Get battery info</p>
</td>
</tr>
<tr id="row1713316577554"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p14171441118"><a name="p14171441118"></a><a name="p14171441118"></a>int32_t GetVoltage(int32_t& voltage);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p17421321134612"><a name="p17421321134612"></a><a name="p17421321134612"></a>Get battery voltage</p>
</td>
</tr>
<tr id="row171331657185514"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p12841932114117"><a name="p12841932114117"></a><a name="p12841932114117"></a>int32_t GetTemperature(int32_t& temperature);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1874202174615"><a name="p1874202174615"></a><a name="p1874202174615"></a>Get battery temperature</p>
</td>
</tr>
<tr id="row41331557165518"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p92831132184119"><a name="p92831132184119"></a><a name="p92831132184119"></a>int32_t GetHealthState(BatteryHealthState& healthState);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p474262184610"><a name="p474262184610"></a><a name="p474262184610"></a>Get battery health state</p>
</td>
</tr>
<tr id="row77021769584"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8283123284110"><a name="p8283123284110"></a><a name="p8283123284110"></a>int32_t GetPluggedType(BatteryPluggedType& pluggedType);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107422021204615"><a name="p107422021204615"></a><a name="p107422021204615"></a>Get plugged type</p>
</td>
</tr>
<tr id="row71857914585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p4282032114118"><a name="p4282032114118"></a><a name="p4282032114118"></a>int32_t GetChargeState(BatteryChargeState& chargeState);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p374210219468"><a name="p374210219468"></a><a name="p374210219468"></a>Get charge state</p>
</td>
</tr>
<tr id="row884115357415"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p68421035114115"><a name="p68421035114115"></a><a name="p68421035114115"></a>int32_t GetPresent(bool& present);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1674212113467"><a name="p1674212113467"></a><a name="p1674212113467"></a>Get if battery is present</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p172641732134117"><a name="p172641732134117"></a><a name="p172641732134117"></a>int32_t GetTechnology(std::string& technology);</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p10742182114462"><a name="p10742182114462"></a><a name="p10742182114462"></a>Get battery technology</p>
</td>
</tr>
<tr id="row1452521025813"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p033128174618"><a name="p033128174618"></a><a name="p033128174618"></a>int32_t SetChargingLimit(const std::vector<ChargingLimit>& chargingLimit);</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p16761419154811"><a name="p16761419154811"></a><a name="p16761419154811"></a>Set charging limit</p>
</td>
</tr>
<tr id="row172902161193"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1249042564815"><a name="p1249042564815"></a><a name="p1249042564815"></a>int32_t GetChargeType(ChargeType& chargeType);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p17591149104819"><a name="p17591149104819"></a><a name="p17591149104819"></a>Get charge type</p>
</td>
</tr>
<tr id="row1948179195"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p5783143154816"><a name="p5783143154816"></a><a name="p5783143154816"></a>int32_t SetBatteryConfig(const std::string& sceneName, const std::string& value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1759749134818"><a name="p1759749134818"></a><a name="p1759749134818"></a>Set battery config</p>
</td>
</tr>
<tr id="row1331121813197"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p2728173711481"><a name="p2728173711481"></a><a name="p2728173711481"></a>int32_t GetBatteryConfig(const std::string& sceneName, std::string& value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107591749104810"><a name="p107591749104810"></a><a name="p107591749104810"></a>Get battery config</p>
</td>
</tr>
<tr id="row218845471539"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1688455171537"><a name="p1688455171537"></a><a name="p1688455171537"></a>int32_t IsBatteryConfigSupported(const std::string& sceneName, bool& value);</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p17884557153719"><a name="p17884557153719"></a><a name="p17884557153719"></a>Check if battery config is supported</p>
</td>
</tr>
</tbody>
</table>

### Usage Instructions<a name="section129654513264"></a>

The core function of this repository is to provide battery management driver capability interfaces for upper-layer system services. The provided driver capability interfaces are unified as HDI interface layer.

The following sample code demonstrates how to use the Battery HDI interface:

```
#include "v2_0/ibattery_interface.h"
#include "battery_hdi_client.h"

using namespace OHOS::HDI::Battery::V2_0;

class BatteryCallbackImpl : public IBatteryCallback {
public:
    int32_t OnBatteryCallback(const BatteryInfo& event) override
    {
        HDF_LOGI("BatteryCallback: capacity=%{public}d, voltage=%{public}d, temperature=%{public}d", 
                 event.capacity, event.voltage, event.temperature);
        return 0;
    }
};

static int32_t BatteryHdiSample(void)
{
    int32_t ret;
    sptr<IBatteryInterface> g_batteryInterface = BatteryHdiClient::GetInstance();

    if (g_batteryInterface == nullptr) {
        HDF_LOGE("get battery interface failed");
        return HDF_FAILURE;
    }

    // Register battery callback
    sptr<IBatteryCallback> callback = new (std::nothrow) BatteryCallbackImpl();
    ret = g_batteryInterface->Register(callback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("register battery callback failed");
        return ret;
    }

    // Get battery capacity
    int32_t capacity;
    ret = g_batteryInterface->GetCapacity(capacity);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get capacity failed");
        return ret;
    }

    // Get battery voltage
    int32_t voltage;
    ret = g_batteryInterface->GetVoltage(voltage);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get voltage failed");
        return ret;
    }

    // Get battery temperature
    int32_t temperature;
    ret = g_batteryInterface->GetTemperature(temperature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get temperature failed");
        return ret;
    }

    // Get health state
    BatteryHealthState healthState;
    ret = g_batteryInterface->GetHealthState(healthState);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get health state failed");
        return ret;
    }

    // Get charge state
    BatteryChargeState chargeState;
    ret = g_batteryInterface->GetChargeState(chargeState);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get charge state failed");
        return ret;
    }

    // Get if battery is present
    bool present;
    ret = g_batteryInterface->GetPresent(present);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get present failed");
        return ret;
    }

    // Get battery technology
    std::string technology;
    ret = g_batteryInterface->GetTechnology(technology);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get technology failed");
        return ret;
    }

    // Get charge type
    ChargeType chargeType;
    ret = g_batteryInterface->GetChargeType(chargeType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get charge type failed");
        return ret;
    }

    // Get average current
    int32_t curAverage;
    ret = g_batteryInterface->GetCurrentAverage(curAverage);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get current average failed");
        return ret;
    }

    // Get instantaneous current
    int32_t curNow;
    ret = g_batteryInterface->GetCurrentNow(curNow);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get current now failed");
        return ret;
    }

    // Get battery info
    BatteryInfo info;
    ret = g_batteryInterface->GetBatteryInfo(info);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get battery info failed");
        return ret;
    }

    // Get battery config
    std::string value;
    ret = g_batteryInterface->GetBatteryConfig("scene_name", value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get battery config failed");
        return ret;
    }

    // Set battery config
    ret = g_batteryInterface->SetBatteryConfig("scene_name", "value");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set battery config failed");
        return ret;
    }

    // Check if battery config is supported
    bool isSupported;
    ret = g_batteryInterface->IsBatteryConfigSupported("scene_name", isSupported);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("check battery config supported failed");
        return ret;
    }

    // Unregister battery callback
    ret = g_batteryInterface->UnRegister();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("unregister battery callback failed");
        return ret;
    }

    return HDF_SUCCESS;
}
```

## Related Repositories<a name="section1371113476307"></a>

[Driver Subsystem](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[drivers\_framework](https://gitee.com/openharmony/drivers_framework/blob/master/README_zh.md)

[drivers\_adapter](https://gitee.com/openharmony/drivers_adapter/blob/master/README_zh.md)

[drivers\_interface](https://gitee.com/openharmony/drivers_interface)

[drivers\_peripheral](https://gitee.com/openharmony/drivers_peripheral)
