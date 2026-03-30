# Power<a name="ZH-CN_TOPIC_0000001124650034"></a>

-   [Introduction](#section11660541593)
-   [Directory](#section161941989596)
    -   [Interface Description](#section1551164914237)
    -   [Usage Instructions](#section129654513264)

-   [Related Repositories](#section1371113476307)

## Introduction<a name="section11660541593"></a>

This repository contains the Power module HDI (Hardware Driver Interface) definitions and implementations, providing power management driver capability interfaces for upper-layer system services. The Power HDI interfaces mainly include:

-   **Suspend/Resume**: Responsible for system suspend and resume management, including active suspend, force suspend, stop suspend, etc.
-   **RunningLock**: Responsible for running lock management, including hold, release, timer handling, etc.
-   **Hibernate**: Responsible for system hibernation functionality.
-   **PowerConfig**: Responsible for power configuration management, supporting getting and setting power configuration items.

## Directory<a name="section161941989596"></a>

The source code directory structure is as follows:

```
/drivers/peripheral/power
├── etc                      # Power module configuration files
│   └── para                 # Parameter configuration files
├── interfaces              # Power module driver capability interfaces for upper-layer services
│   └── hdi_service          # HDI layer framework code
│       ├── profile          # Configuration files
│       └── src              # HDI layer source code
├── test                     # Power module test code
│   ├── unittest             # Unit tests
│   └── fuzztest             # Fuzz tests
└── utils                    # Utility code
```

### Interface Description<a name="section1551164914237"></a>

The Power driver module provides interfaces to upper-layer system services through the HDI layer, with main functions including: system suspend/resume, running lock management, power configuration, etc. The provided interfaces are shown in [Table1 Power HDI Interface List](#table1513255710559):

**Table 1**  Power HDI Interface List

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" align="center" valign="top" width="12.121212121212123%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>Header File</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="64.95649564956496%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>Interface Name</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="22.922292229222922%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>Function Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row13132357165514"><td class="cellrowborder" rowspan="13" valign="top" width="12.121212121212123%" headers="mcps1.2.4.1.1 "><p id="p829618389386"><a name="p829618389386"></a><a name="p829618389386"></a></p>
<p id="p35261387384"><a name="p35261387384"></a><a name="p35261387384"></a></p>
<p id="p776383812388"><a name="p776383812388"></a><a name="p776383812388"></a></p>
<p id="p11950123812382"><a name="p11950123812382"></a><a name="p11950123812382"></a></p>
<p id="p13168103915381"><a name="p13168103915381"></a><a name="p13168103915381"></a></p>
<p id="p825185015460"><a name="p825185015460"></a><a name="p825185015460"></a>v1_3/ipower_interface.h</p>
</td>
<td class="cellrowborder" valign="top" width="64.95649564956496%" headers="mcps1.2.4.1.2 "><p id="p1365411515117"><a name="p1365411515117"></a><a name="p1365411515117"></a>int32_t SetSuspendTag(const std::string &tag);</p>
</td>
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p041814588404"><a name="p041814588404"></a><a name="p041814588404"></a>Set suspend tag</p>
</td>
</tr>
<tr id="row9132135715515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1398804043612"><a name="p1398804043612"></a><a name="p1398804043612"></a>int32_t StartSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1341845816404"><a name="p1341845816404"></a><a name="p1341845816404"></a>Start suspend</p>
</td>
</tr>
<tr id="row171330575555"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1974125024812"><a name="p1974125024812"></a><a name="p1974125024812"></a>int32_t StopSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1041815816403"><a name="p1041815816403"></a><a name="p1041815816403"></a>Stop suspend</p>
</td>
</tr>
<tr id="row576145883720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8761658183714"><a name="p8761658183714"></a><a name="p8761658183714"></a>int32_t ForceSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p15418165812409"><a name="p15418165812409"></a><a name="p15418165812409"></a>Force suspend</p>
</td>
</tr>
<tr id="row1957862120383"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p55781217381"><a name="p55781217381"></a><a name="p55781217381"></a>int32_t Hibernate();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1641875834010"><a name="p1641875834010"></a><a name="p1641875834010"></a>System hibernate</p>
</td>
</tr>
<tr id="row127635162380"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p3763916143816"><a name="p3763916143816"></a><a name="p3763916143816"></a>int32_t SuspendBlock(const std::string &name);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418195874019"><a name="p10418195874019"></a><a name="p10418195874019"></a>Block suspend</p>
</td>
</tr>
<tr id="row14230131383819"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1723081310386"><a name="p1723081310386"></a><a name="p1723081310386"></a>int32_t SuspendUnblock(const std::string &name);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418658184012"><a name="p10418658184012"></a><a name="p10418658184012"></a>Unblock suspend</p>
</td>
</tr>
<tr id="row159636983816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p89635916383"><a name="p89635916383"></a><a name="p89635916383"></a>int32_t PowerDump(std::string &info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p19418205894012"><a name="p19418205894012"></a><a name="p19418205894012"></a>Power state dump</p>
</td>
</tr>
<tr id="row76872047153720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1368818472376"><a name="p1368818472376"></a><a name="p1368818472376"></a>int32_t GetWakeupReason(std::string &reason);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p144182582405"><a name="p144182582405"></a><a name="p144182582405"></a>Get wakeup reason</p>
</td>
</tr>
<tr id="row1713316577554"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p14171441118"><a name="p14171441118"></a><a name="p14171441118"></a>int32_t SetPowerConfig(const std::string &sceneName, const std::string &value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p17421321134612"><a name="p17421321134612"></a><a name="p17421321134612"></a>Set power config</p>
</td>
</tr>
<tr id="row171331657185514"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p12841932114117"><a name="p12841932114117"></a><a name="p12841932114117"></a>int32_t GetPowerConfig(const std::string &sceneName, std::string &value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1874202174615"><a name="p1874202174615"></a><a name="p1874202174615"></a>Get power config</p>
</td>
</tr>
<tr id="row41331557165518"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p92831132184119"><a name="p92831132184119"></a><a name="p92831132184119"></a>int32_t RegisterCallback(const sptr<IPowerHdiCallback> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p474262184610"><a name="p474262184610"></a><a name="p474262184610"></a>Register power callback</p>
</td>
</tr>
<tr id="row112233445566"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p112233445566"><a name="p112233445566"></a><a name="p112233445566"></a>int32_t RegisterPowerCallbackExt(const sptr<V1_3::IPowerHdiCallbackExt> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p112233445567"><a name="p112233445567"></a><a name="p112233445567"></a>Register power extension callback</p>
</td>
</tr>
<tr id="row77021769584"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8283123284110"><a name="p8283123284110"></a><a name="p8283123284110"></a>int32_t UnRegisterPowerCallbackExt(const sptr<V1_3::IPowerHdiCallbackExt> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107422021204615"><a name="p107422021204615"></a><a name="p107422021204615"></a>Unregister power extension callback</p>
</td>
</tr>
<tr id="row1513316577555"><td class="cellrowborder" rowspan="7" valign="top" width="12.121212121212123%" headers="mcps1.2.4.1.1 "><p id="p14171441119"><a name="p14171441119"></a><a name="p14171441119"></a></p>
<p id="p154814318411"><a name="p154814318411"></a><a name="p154814318411"></a></p>
<p id="p3481154311419"><a name="p3481154311419"></a><a name="p3481154311419"></a></p>
<p id="p57063567464"><a name="p57063567464"></a><a name="p57063567464"></a></p>
<p id="p2133757135511"><a name="p2133757135511"></a><a name="p2133757135511"></a></p>
<p id="p1476175815373"><a name="p1476175815373"></a><a name="p1476175815373"></a>v1_2/running_lock_types.h</p>
</td>
<td class="cellrowborder" valign="top" width="64.95649564956496%" headers="mcps1.2.4.1.2 "><p id="p228510326415"><a name="p228510326415"></a><a name="p228510326415"></a>int32_t HoldRunningLock(const RunningLockInfo &info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p17421321134613"><a name="p17421321134613"></a><a name="p17421321134613"></a>Hold running lock</p>
</td>
</tr>
<tr id="row171331657185515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p12841932114118"><a name="p12841932114118"></a><a name="p12841932114118"></a>int32_t UnholdRunningLock(const RunningLockInfo &info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1874202174616"><a name="p1874202174616"></a><a name="p1874202174616"></a>Unhold running lock</p>
</td>
</tr>
<tr id="row41331557165519"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p92831132184110"><a name="p92831132184110"></a><a name="p92831132184110"></a>int32_t HoldRunningLockExt(const RunningLockInfo &info, uint64_t lockid, const std::string &bundleName);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p474262184611"><a name="p474262184611"></a><a name="p474262184611"></a>Hold extended running lock</p>
</td>
</tr>
<tr id="row77021769585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8283123284111"><a name="p8283123284111"></a><a name="p8283123284111"></a>int32_t UnholdRunningLockExt(const RunningLockInfo &info, uint64_t lockid, const std::string &bundleName);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107422021204616"><a name="p107422021204616"></a><a name="p107422021204616"></a>Unhold extended running lock</p>
</td>
</tr>
<tr id="row71857914586"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p4282032114119"><a name="p4282032114119"></a><a name="p4282032114119"></a>int32_t RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback> &iPowerRunningLockCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p374210219469"><a name="p374210219469"></a><a name="p374210219469"></a>Register running lock callback</p>
</td>
</tr>
<tr id="row884115357416"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p68421035114116"><a name="p68421035114116"></a><a name="p68421035114116"></a>int32_t UnRegisterRunningLockCallback();</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1674212113468"><a name="p1674212113468"></a><a name="p1674212113468"></a>Unregister running lock callback</p>
</td>
</tr>
</tbody>
</table>

### Usage Instructions<a name="section129654513264"></a>

The core function of this repository is to provide power management driver capability interfaces for upper-layer system services. The provided driver capability interfaces are unified as HDI interface layer.

The following sample code demonstrates how to use the Power HDI interface:

```
#include "v1_3/ipower_interface.h"
#include "v1_2/running_lock_types.h"
#include "ipower_hdi_callback.h"
#include "power_hdi_client.h"

using namespace OHOS::HDI::Power::V1_3;

static int32_t PowerHdiSample(void)
{
    int32_t ret;
    sptr<IPowerInterface> g_powerInterface = PowerHdiClient::GetInstance();

    if (g_powerInterface == nullptr) {
        HDF_LOGE("get power interface failed");
        return HDF_FAILURE;
    }

    // Set suspend tag
    ret = g_powerInterface->SetSuspendTag("test_tag");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set suspend tag failed");
        return ret;
    }

    // Start suspend
    ret = g_powerInterface->StartSuspend();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("start suspend failed");
        return ret;
    }

    // Stop suspend
    ret = g_powerInterface->StopSuspend();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("stop suspend failed");
        return ret;
    }

    // Hold running lock
    RunningLockInfo lockInfo;
    lockInfo.type = RunningLockType::RUNNINGLOCK_SCREEN;
    lockInfo.name = "screen_lock";
    lockInfo.timeoutMs = 5000;
    ret = g_powerInterface->HoldRunningLock(lockInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("hold running lock failed");
        return ret;
    }

    // Unhold running lock
    ret = g_powerInterface->UnholdRunningLock(lockInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("unhold running lock failed");
        return ret;
    }

    // Get wakeup reason
    std::string wakeupReason;
    ret = g_powerInterface->GetWakeupReason(wakeupReason);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get wakeup reason failed");
        return ret;
    }

    // Get power config
    std::string value;
    ret = g_powerInterface->GetPowerConfig("screen_off_timeout", value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get power config failed");
        return ret;
    }

    // Set power config
    ret = g_powerInterface->SetPowerConfig("screen_off_timeout", "30000");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set power config failed");
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
