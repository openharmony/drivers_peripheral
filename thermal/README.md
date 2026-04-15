# Thermal<a name="ZH-CN_TOPIC_0000001124650035"></a>

-   [Introduction](#section11660541593)
-   [Directory](#section161941989596)
    -   [Interface Description](#section1551164914237)
    -   [Usage Instructions](#section129654513264)

-   [Related Repositories](#section1371113476307)

## Introduction<a name="section11660541593"></a>

This repository contains the Thermal module HDI (Hardware Driver Interface) definitions and implementations, providing temperature management driver capability interfaces for upper-layer system services. The Thermal HDI interfaces mainly include:

-   **Thermal Zone**: Responsible for obtaining thermal zone temperature information.
-   **Thermal Mitigation**: Responsible for thermal mitigation strategy management, including CPU frequency adjustment, GPU frequency adjustment, battery current limit, etc.
-   **CPU Isolation**: Responsible for CPU core isolation management.
-   **Callback**: Responsible for thermal event callback notifications.

## Directory<a name="section161941989596"></a>

The source code directory structure is as follows:

```
/drivers/peripheral/thermal
├── etc                      # Thermal module configuration files
├── interfaces              # Thermal module driver capability interfaces for upper-layer services
│   └── hdi_service          # HDI layer framework code
│       ├── include          # Header files
│       ├── profile          # Configuration files
│       └── src              # HDI layer source code
├── test                     # Thermal module test code
│   ├── unittest             # Unit tests
│   └── fuzztest             # Fuzz tests
└── utils                    # Utility code
```

### Interface Description<a name="section1551164914237"></a>

The Thermal driver module provides interfaces to upper-layer system services through the HDI layer, with main functions including: obtaining thermal zone information, setting thermal mitigation strategies, CPU isolation, etc. The provided interfaces are shown in [Table1 Thermal HDI Interface List](#table1513255710559):

**Table 1**  Thermal HDI Interface List

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" align="center" valign="top" width="12.121212121212123%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>Header File</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="64.95649564956496%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>Interface Name</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="22.922292229222922%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>Function Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row13132357165514"><td class="cellrowborder" rowspan="9" valign="top" width="12.121212121212123%" headers="mcps1.2.4.1.1 "><p id="p829618389386"><a name="p829618389386"></a><a name="p829618389386"></a></p>
<p id="p35261387384"><a name="p35261387384"></a><a name="p35261387384"></a></p>
<p id="p776383812388"><a name="p776383812388"></a><a name="p776383812388"></a></p>
<p id="p11950123812382"><a name="p11950123812382"></a><a name="p11950123812382"></a></p>
<p id="p13168103915381"><a name="p13168103915381"></a><a name="p13168103915381"></a></p>
<p id="p825185015460"><a name="p825185015460"></a><a name="p825185015460"></a>v1_1/ithermal_interface.h</p>
</td>
<td class="cellrowborder" valign="top" width="64.95649564956496%" headers="mcps1.2.4.1.2 "><p id="p1365411515117"><a name="p1365411515117"></a><a name="p1365411515117"></a>int32_t SetCpuFreq(int32_t freq);</p>
</td>
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p041814588404"><a name="p041814588404"></a><a name="p041814588404"></a>Set CPU frequency</p>
</td>
</tr>
<tr id="row9132135715515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1398804043612"><a name="p1398804043612"></a><a name="p1398804043612"></a>int32_t SetGpuFreq(int32_t freq);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1341845816404"><a name="p1341845816404"></a><a name="p1341845816404"></a>Set GPU frequency</p>
</td>
</tr>
<tr id="row171330575555"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1974125024812"><a name="p1974125024812"></a><a name="p1974125024812"></a>int32_t SetBatteryCurrent(int32_t current);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1041815816403"><a name="p1041815816403"></a><a name="p1041815816403"></a>Set battery current</p>
</td>
</tr>
<tr id="row576145883720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8761658183714"><a name="p8761658183714"></a><a name="p8761658183714"></a>int32_t GetThermalZoneInfo(HdfThermalCallbackInfo& event);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p15418165812409"><a name="p15418165812409"></a><a name="p15418165812409"></a>Get thermal zone info</p>
</td>
</tr>
<tr id="row1957862120383"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p55781217381"><a name="p55781217381"></a><a name="p55781217381"></a>int32_t IsolateCpu(int32_t num);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1641875834010"><a name="p1641875834010"></a><a name="p1641875834010"></a>Isolate CPU core</p>
</td>
</tr>
<tr id="row127635162380"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p3763916143816"><a name="p3763916143816"></a><a name="p3763916143816"></a>int32_t Register(const sptr<IThermalCallback>& callbackObj);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418195874019"><a name="p10418195874019"></a><a name="p10418195874019"></a>Register thermal callback</p>
</td>
</tr>
<tr id="row14230131383819"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1723081310386"><a name="p1723081310386"></a><a name="p1723081310386"></a>int32_t Unregister();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418658184012"><a name="p10418658184012"></a><a name="p10418658184012"></a>Unregister thermal callback</p>
</td>
</tr>
<tr id="row159636983816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p89635916383"><a name="p89635916383"></a><a name="p89635916383"></a>int32_t RegisterFanCallback(const sptr<IFanCallback>& callbackObj);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p19418205894012"><a name="p19418205894012"></a><a name="p19418205894012"></a>Register fan callback</p>
</td>
</tr>
<tr id="row76872047153720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1368818472376"><a name="p1368818472376"></a><a name="p1368818472376"></a>int32_t UnregisterFanCallback();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p144182582405"><a name="p144182582405"></a><a name="p144182582405"></a>Unregister fan callback</p>
</td>
</tr>
</tbody>
</table>

### Usage Instructions<a name="section129654513264"></a>

The core function of this repository is to provide temperature management driver capability interfaces for upper-layer system services. The provided driver capability interfaces are unified as HDI interface layer.

The following sample code demonstrates how to use the Thermal HDI interface:

```
#include "v1_1/ithermal_interface.h"
#include "thermal_hdi_client.h"

using namespace OHOS::HDI::Thermal::V1_1;

class ThermalCallbackImpl : public IThermalCallback {
public:
    int32_t OnThermalCallback(HdfThermalCallbackInfo& event) override
    {
        HDF_LOGI("ThermalCallback: zoneId=%{public}d, temp=%{public}d", 
                 event.zoneId, event.temperature);
        return 0;
    }
};

static int32_t ThermalHdiSample(void)
{
    int32_t ret;
    sptr<IThermalInterface> g_thermalInterface = ThermalHdiClient::GetInstance();

    if (g_thermalInterface == nullptr) {
        HDF_LOGE("get thermal interface failed");
        return HDF_FAILURE;
    }

    // Register thermal callback
    sptr<IThermalCallback> callback = new (std::nothrow) ThermalCallbackImpl();
    ret = g_thermalInterface->Register(callback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("register thermal callback failed");
        return ret;
    }

    // Set CPU frequency
    ret = g_thermalInterface->SetCpuFreq(2000000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set cpu freq failed");
        return ret;
    }

    // Set GPU frequency
    ret = g_thermalInterface->SetGpuFreq(800000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set gpu freq failed");
        return ret;
    }

    // Set battery current
    ret = g_thermalInterface->SetBatteryCurrent(1000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set battery current failed");
        return ret;
    }

    // Isolate CPU core
    ret = g_thermalInterface->IsolateCpu(4);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("isolate cpu failed");
        return ret;
    }

    // Get thermal zone info
    HdfThermalCallbackInfo event;
    ret = g_thermalInterface->GetThermalZoneInfo(event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get thermal zone info failed");
        return ret;
    }

    // Unregister thermal callback
    ret = g_thermalInterface->Unregister();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("unregister thermal callback failed");
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
