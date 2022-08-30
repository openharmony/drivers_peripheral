# vibrator

- [简介](##简介)
- [目录](##目录)
- [说明](##说明)
  - [接口说明](###接口说明)
  - [使用说明](###使用说明)

- [相关仓](##相关仓)

## 简介

Vibrator驱动模型主要包含Vibrator（马达）相关的HDI接口与实现，提供Vibrator HDI（ Hardware Device Interface ）能力接口，支持三种振动效果：静态HCS配置的时间序列，动态配置持续时间，动态配置持续时间、振动强度、振动频率。调用StartOnce接口动态配置持续振动时间；调用StartEffect接口启动静态配置的振动效果；调用EnableVibratorModulation接口启动动态配置的振动效果。

**图 1** Vibrator驱动模型图

![Vibrator驱动模型图](figures/Vibrator%E9%A9%B1%E5%8A%A8%E6%A8%A1%E5%9E%8B%E5%9B%BE.png)

## 目录

Vibraor驱动下源代码目录结构如下所示：

```
/drivers/peripheral/vibrator
├── chipset          # vibrator模块器件驱动代码
├── hal              # vibrator模块hal层代码
│   ├── include      # vibrator模块hal层内部头文件
│   └── src          # vibrator模块hal层代码的实现
├── interfaces       # vibrator模块对上层服务提供的驱动能力接口
│   └── include      # vibrator模块对外提供的接口定义
└── test             # vibrator模块测试代码
    └── unittest     # vibrator模块单元测试代码
```

## 说明

### 接口说明

马达主要提供的功能：触发振动，停止振动。开发能力如下表1：

**表 1**马达的主要接口

| 接口名                                                       | 功能描述                                                     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| int32_t  StartOnce(uint32_t duration)                        | 按照指定持续时间触发振动，duration为振动持续时长。           |
| int32_t  Start(const char *effectType)                       | 按照指定预置效果启动马达，effectType表示预置的振动效果串。   |
| int32_t  Stop(enum VibratorMode mode)                        | 按照指定的振动模式停止振动。                                 |
| int32_t EnableVibratorModulation(uint32_t duration, int32_t intensity, int32_t frequency) | 按照指定振幅，频率、持续时间触发振动马达，duration为振动持续时长，intensity为振动强度，frequency为振动频率。 |
| int32_t GetVibratorInfo(struct VibratorInfo **vibratorInfo); | 获取马达信息，包括是否支持振幅和频率的设置及振幅和频率的设置范围 。 |

### 使用说明

代码示例

```c++
#include "vibrator_if.h"

enum VibratorMode {
    VIBRATOR_MODE_ONCE   = 0,    // 指定时间内的一次振动
    VIBRATOR_MODE_PRESET = 1,    // 指定预置效果的周期性振动
};

void VibratorSample(void)
{
    int32_t startRet;
    int32_t endRet;
    uint32_t g_duration = 1000;
    uint32_t g_sleepTime1 = 2000;
    uint32_t g_sleepTime2 = 5000;
    int32_t g_intensity1 = 30;
    int32_t g_frequency1 = 200;
    const char *g_timeSequence = "haptic.clock.timer";
    struct VibratorInfo *g_vibratorInfo = nullptr;
    /* 创建马达接口实例 */
    struct VibratorInterface *g_vibratorDev = NewVibratorInterfaceInstance();
    if (g_vibratorDev == NULL) {
        return;
    }
    /* 获取马达信息，包括是否支持振幅和频率的设置及振幅和频率的设置范围。 */
    startRet = g_vibratorDev->GetVibratorInfo(&g_vibratorInfo);
    if (startRet != 0) {
        return;
    }
    /* 按照指定持续时间触发振动*/
    startRet = g_vibratorDev->StartOnce(g_duration);
    if (startRet != 0) {
        return;
    }
    OsalMSleep(g_sleepTime1);
    /* 按照指定的振动模式停止振动 */
    endRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    if (endRet != 0) {
        return;
    }
    /* 按照指定预置效果启动马达 */
    startRet = g_vibratorDev->Start(g_timeSequence);
    if (endRet != 0) {
        return;
    }
    OsalMSleep(g_sleepTime2);
    /* 按照指定的振动模式停止振动 */
    endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    if (endRet != 0) {
        return;
    }
    /* 按照指定振幅，频率、持续时间触发振动马达。 */
    startRet = g_vibratorDev->EnableVibratorModulation(g_duration, g_intensity1, g_frequency1);
    if (endRet != 0) {
        return;
    }
    OsalMSleep(g_sleepTime1);
    /* 按照指定的振动模式停止振动 */
    startRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    if (endRet != 0) {
        return;
    }
    /* 释放传感器接口实例 */
    ret = FreeVibratorInterfaceInstance();
    if (ret != 0) {
        return;
    }
}
```

## 相关仓

[驱动子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[drivers_hdf_core](https://gitee.com/openharmony/drivers_hdf_core/blob/master/README_zh.md)

[drivers_peripheral](https://gitee.com/openharmony/drivers_peripheral)