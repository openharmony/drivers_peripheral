# Power<a name="ZH-CN_TOPIC_0000001124650034"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
    -   [接口说明](#section1551164914237)
    -   [使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

该仓下主要包含Power模块HDI（Hardware Driver Interface）接口定义及其实现，对上层系统服务提供电源管理驱动能力接口。Power HDI接口主要包括以下几大类：

-   **Suspend/Resume**：负责系统的挂起和恢复管理，包括主动挂起、强制挂起、停止挂起等操作；
-   **RunningLock**：负责运行锁的管理，包括运行锁的持有、释放、计时器处理等操作；
-   **Hibernate**：负责系统休眠功能；
-   **PowerConfig**：负责电源配置的管理，支持获取和设置电源配置项。

## 目录<a name="section161941989596"></a>

该仓下源代码目录结构如下所示：

```
/drivers/peripheral/power
├── etc                      # power模块配置文件
│   └── para                 # 参数配置文件
├── interfaces              # power模块对上层服务提供的驱动能力接口
│   └── hdi_service          # hdi层框架代码
│       ├── profile          # 配置文件
│       └── src              # hdi层源代码
├── test                     # power模块的测试代码
│   ├── unittest             # 单元测试
│   └── fuzztest             # 模糊测试
└── utils                    # 工具类代码
```

### 接口说明<a name="section1551164914237"></a>

Power驱动模块通过HDI层对上层系统服务提供接口，主要功能包括：系统挂起/恢复、运行锁管理、电源配置等。提供的接口说明如[表1 Power HDI接口列表](#table1513255710559)所示：

**表 1**  Power HDI接口列表

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" align="center" valign="top" width="12.121212121212123%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>头文件</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="64.95649564956496%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>接口名称</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="22.922292229222922%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>功能描述</p>
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
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p041814588404"><a name="p041814588404"></a><a name="p041814588404"></a>设置挂起标签</p>
</td>
</tr>
<tr id="row9132135715515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1398804043612"><a name="p1398804043612"></a><a name="p1398804043612"></a>int32_t StartSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1341845816404"><a name="p1341845816404"></a><a name="p1341845816404"></a>开始挂起</p>
</td>
</tr>
<tr id="row171330575555"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1974125024812"><a name="p1974125024812"></a><a name="p1974125024812"></a>int32_t StopSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1041815816403"><a name="p1041815816403"></a><a name="p1041815816403"></a>停止挂起</p>
</td>
</tr>
<tr id="row576145883720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8761658183714"><a name="p8761658183714"></a><a name="p8761658183714"></a>int32_t ForceSuspend();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p15418165812409"><a name="p15418165812409"></a><a name="p15418165812409"></a>强制挂起</p>
</td>
</tr>
<tr id="row1957862120383"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p55781217381"><a name="p55781217381"></a><a name="p55781217381"></a>int32_t Hibernate();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1641875834010"><a name="p1641875834010"></a><a name="p1641875834010"></a>系统休眠</p>
</td>
</tr>
<tr id="row127635162380"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p3763916143816"><a name="p3763916143816"></a><a name="p3763916143816"></a>int32_t SuspendBlock(const std::string &name);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418195874019"><a name="p10418195874019"></a><a name="p10418195874019"></a>阻止挂起</p>
</td>
</tr>
<tr id="row14230131383819"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1723081310386"><a name="p1723081310386"></a><a name="p1723081310386"></a>int32_t SuspendUnblock(const std::string &name);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418658184012"><a name="p10418658184012"></a><a name="p10418658184012"></a>取消阻止挂起</p>
</td>
</tr>
<tr id="row159636983816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p89635916383"><a name="p89635916383"></a><a name="p89635916383"></a>int32_t PowerDump(std::string &info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p19418205894012"><a name="p19418205894012"></a><a name="p19418205894012"></a>电源状态导出</p>
</td>
</tr>
<tr id="row76872047153720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1368818472376"><a name="p1368818472376"></a><a name="p1368818472376"></a>int32_t GetWakeupReason(std::string &reason);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p144182582405"><a name="p144182582405"></a><a name="p144182582405"></a>获取唤醒原因</p>
</td>
</tr>
<tr id="row1713316577554"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p14171441118"><a name="p14171441118"></a><a name="p14171441118"></a>int32_t SetPowerConfig(const std::string &sceneName, const std::string &value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p17421321134612"><a name="p17421321134612"></a><a name="p17421321134612"></a>设置电源配置</p>
</td>
</tr>
<tr id="row171331657185514"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p12841932114117"><a name="p12841932114117"></a><a name="p12841932114117"></a>int32_t GetPowerConfig(const std::string &sceneName, std::string &value);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1874202174615"><a name="p1874202174615"></a><a name="p1874202174615"></a>获取电源配置</p>
</td>
</tr>
<tr id="row41331557165518"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p92831132184119"><a name="p92831132184119"></a><a name="p92831132184119"></a>int32_t RegisterCallback(const sptr<IPowerHdiCallback> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p474262184610"><a name="p474262184610"></a><a name="p474262184610"></a>注册电源回调</p>
</td>
</tr>
<tr id="row112233445566"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p112233445566"><a name="p112233445566"></a><a name="p112233445566"></a>int32_t RegisterPowerCallbackExt(const sptr<V1_3::IPowerHdiCallbackExt> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p112233445567"><a name="p112233445567"></a><a name="p112233445567"></a>注册电源扩展回调</p>
</td>
</tr>
<tr id="row77021769584"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8283123284110"><a name="p8283123284110"></a><a name="p8283123284110"></a>int32_t UnRegisterPowerCallbackExt(const sptr<V1_3::IPowerHdiCallbackExt> &ipowerHdiCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107422021204615"><a name="p107422021204615"></a><a name="p107422021204615"></a>注销电源扩展回调</p>
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
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p17421321134613"><a name="p17421321134613"></a><a name="p17421321134613"></a>持有运行锁</p>
</td>
</tr>
<tr id="row171331657185515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p12841932114118"><a name="p12841932114118"></a><a name="p12841932114118"></a>int32_t UnholdRunningLock(const RunningLockInfo &info);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1874202174616"><a name="p1874202174616"></a><a name="p1874202174616"></a>释放运行锁</p>
</td>
</tr>
<tr id="row41331557165519"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p92831132184110"><a name="p92831132184110"></a><a name="p92831132184110"></a>int32_t HoldRunningLockExt(const RunningLockInfo &info, uint64_t lockid, const std::string &bundleName);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p474262184611"><a name="p474262184611"></a><a name="p474262184611"></a>持有扩展运行锁</p>
</td>
</tr>
<tr id="row77021769585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8283123284111"><a name="p8283123284111"></a><a name="p8283123284111"></a>int32_t UnholdRunningLockExt(const RunningLockInfo &info, uint64_t lockid, const std::string &bundleName);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p107422021204616"><a name="p107422021204616"></a><a name="p107422021204616"></a>释放扩展运行锁</p>
</td>
</tr>
<tr id="row71857914586"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p4282032114119"><a name="p4282032114119"></a><a name="p4282032114119"></a>int32_t RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback> &iPowerRunningLockCallback);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p374210219469"><a name="p374210219469"></a><a name="p374210219469"></a>注册运行锁回调</p>
</td>
</tr>
<tr id="row884115357416"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p68421035114116"><a name="p68421035114116"></a><a name="p68421035114116"></a>int32_t UnRegisterRunningLockCallback();</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1674212113468"><a name="p1674212113468"></a><a name="p1674212113468"></a>注销运行锁回调</p>
</td>
</tr>
</tbody>
</table>

### 使用说明<a name="section129654513264"></a>

该仓核心功能是提供电源管理驱动能力接口供上层系统服务调用，提供的驱动能力接口统一归属为HDI接口层。

通过如下简要示例代码说明Power HDI接口的使用：

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

    // 设置挂起标签
    ret = g_powerInterface->SetSuspendTag("test_tag");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set suspend tag failed");
        return ret;
    }

    // 开始挂起
    ret = g_powerInterface->StartSuspend();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("start suspend failed");
        return ret;
    }

    // 停止挂起
    ret = g_powerInterface->StopSuspend();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("stop suspend failed");
        return ret;
    }

    // 持有运行锁
    RunningLockInfo lockInfo;
    lockInfo.type = RunningLockType::RUNNINGLOCK_SCREEN;
    lockInfo.name = "screen_lock";
    lockInfo.timeoutMs = 5000;
    ret = g_powerInterface->HoldRunningLock(lockInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("hold running lock failed");
        return ret;
    }

    // 释放运行锁
    ret = g_powerInterface->UnholdRunningLock(lockInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("unhold running lock failed");
        return ret;
    }

    // 获取唤醒原因
    std::string wakeupReason;
    ret = g_powerInterface->GetWakeupReason(wakeupReason);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get wakeup reason failed");
        return ret;
    }

    // 获取电源配置
    std::string value;
    ret = g_powerInterface->GetPowerConfig("screen_off_timeout", value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get power config failed");
        return ret;
    }

    // 设置电源配置
    ret = g_powerInterface->SetPowerConfig("screen_off_timeout", "30000");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set power config failed");
        return ret;
    }

    return HDF_SUCCESS;
}
```

## 相关仓<a name="section1371113476307"></a>

[驱动子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[drivers\_framework](https://gitee.com/openharmony/drivers_framework/blob/master/README_zh.md)

[drivers\_adapter](https://gitee.com/openharmony/drivers_adapter/blob/master/README_zh.md)

[drivers\_interface](https://gitee.com/openharmony/drivers_interface)

[drivers\_peripheral](https://gitee.com/openharmony/drivers_peripheral)
