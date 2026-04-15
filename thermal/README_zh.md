# Thermal<a name="ZH-CN_TOPIC_0000001124650035"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
    -   [接口说明](#section1551164914237)
    -   [使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

该仓下主要包含Thermal模块HDI（Hardware Driver Interface）接口定义及其实现，对上层系统服务提供温度管理驱动能力接口。Thermal HDI接口主要包括以下几大类：

-   **Thermal Zone**：负责获取热区的温度信息；
-   **Thermal Mitigation**：负责热 Mitigation 策略的管理，包括CPU频率调节、GPU频率调节、电池电流限制等；
-   **CPU Isolation**：负责CPU核心的隔离管理；
-   **Callback**：负责thermal事件的回调通知。

## 目录<a name="section161941989596"></a>

该仓下源代码目录结构如下所示：

```
/drivers/peripheral/thermal
├── etc                      # thermal模块配置文件
├── interfaces              # thermal模块对上层服务提供的驱动能力接口
│   └── hdi_service          # hdi层框架代码
│       ├── include          # 头文件目录
│       ├── profile          # 配置文件
│       └── src              # hdi层源代码
├── test                     # thermal模块的测试代码
│   ├── unittest             # 单元测试
│   └── fuzztest             # 模糊测试
└── utils                    # 工具类代码
```

### 接口说明<a name="section1551164914237"></a>

Thermal驱动模块通过HDI层对上层系统服务提供接口，主要功能包括：获取热区信息、设置散热策略、CPU隔离等。提供的接口说明如[表1 Thermal HDI接口列表](#table1513255710559)所示：

**表 1**  Thermal HDI接口列表

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" align="center" valign="top" width="12.121212121212123%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>头文件</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="64.95649564956496%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>接口名称</p>
</th>
<th class="cellrowborder" align="center" valign="top" width="22.922292229222922%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>功能描述</p>
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
<td class="cellrowborder" align="center" valign="top" width="22.922292229222922%" headers="mcps1.2.4.1.3 "><p id="p041814588404"><a name="p041814588404"></a><a name="p041814588404"></a>设置CPU频率</p>
</td>
</tr>
<tr id="row9132135715515"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1398804043612"><a name="p1398804043612"></a><a name="p1398804043612"></a>int32_t SetGpuFreq(int32_t freq);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1341845816404"><a name="p1341845816404"></a><a name="p1341845816404"></a>设置GPU频率</p>
</td>
</tr>
<tr id="row171330575555"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1974125024812"><a name="p1974125024812"></a><a name="p1974125024812"></a>int32_t SetBatteryCurrent(int32_t current);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1041815816403"><a name="p1041815816403"></a><a name="p1041815816403"></a>设置电池电流</p>
</td>
</tr>
<tr id="row576145883720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p8761658183714"><a name="p8761658183714"></a><a name="p8761658183714"></a>int32_t GetThermalZoneInfo(HdfThermalCallbackInfo& event);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p15418165812409"><a name="p15418165812409"></a><a name="p15418165812409"></a>获取热区信息</p>
</td>
</tr>
<tr id="row1957862120383"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p55781217381"><a name="p55781217381"></a><a name="p55781217381"></a>int32_t IsolateCpu(int32_t num);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p1641875834010"><a name="p1641875834010"></a><a name="p1641875834010"></a>隔离CPU核心</p>
</td>
</tr>
<tr id="row127635162380"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p3763916143816"><a name="p3763916143816"></a><a name="p3763916143816"></a>int32_t Register(const sptr<IThermalCallback>& callbackObj);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418195874019"><a name="p10418195874019"></a><a name="p10418195874019"></a>注册thermal回调</p>
</td>
</tr>
<tr id="row14230131383819"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1723081310386"><a name="p1723081310386"></a><a name="p1723081310386"></a>int32_t Unregister();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p10418658184012"><a name="p10418658184012"></a><a name="p10418658184012"></a>注销thermal回调</p>
</td>
</tr>
<tr id="row159636983816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p89635916383"><a name="p89635916383"></a><a name="p89635916383"></a>int32_t RegisterFanCallback(const sptr<IFanCallback>& callbackObj);</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p19418205894012"><a name="p19418205894012"></a><a name="p19418205894012"></a>注册风扇回调</p>
</td>
</tr>
<tr id="row76872047153720"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1368818472376"><a name="p1368818472376"></a><a name="p1368818472376"></a>int32_t UnregisterFanCallback();</p>
</td>
<td class="cellrowborder" align="center" valign="top" headers="mcps1.2.4.1.2 "><p id="p144182582405"><a name="p144182582405"></a><a name="p144182582405"></a>注销风扇回调</p>
</td>
</tr>
</tbody>
</table>

### 使用说明<a name="section129654513264"></a>

该仓核心功能是提供温度管理驱动能力接口供上层系统服务调用，提供的驱动能力接口统一归属为HDI接口层。

通过如下简要示例代码说明Thermal HDI接口的使用：

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

    // 注册thermal回调
    sptr<IThermalCallback> callback = new (std::nothrow) ThermalCallbackImpl();
    ret = g_thermalInterface->Register(callback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("register thermal callback failed");
        return ret;
    }

    // 设置CPU频率
    ret = g_thermalInterface->SetCpuFreq(2000000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set cpu freq failed");
        return ret;
    }

    // 设置GPU频率
    ret = g_thermalInterface->SetGpuFreq(800000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set gpu freq failed");
        return ret;
    }

    // 设置电池电流
    ret = g_thermalInterface->SetBatteryCurrent(1000);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set battery current failed");
        return ret;
    }

    // 隔离CPU核心
    ret = g_thermalInterface->IsolateCpu(4);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("isolate cpu failed");
        return ret;
    }

    // 获取热区信息
    HdfThermalCallbackInfo event;
    ret = g_thermalInterface->GetThermalZoneInfo(event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("get thermal zone info failed");
        return ret;
    }

    // 注销thermal回调
    ret = g_thermalInterface->Unregister();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("unregister thermal callback failed");
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
