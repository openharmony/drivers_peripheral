# Battery 驱动 (peripheral) — Agent 工作指南

> 给 AI 编码助手使用。本目录是 OpenHarmony 电池 HDI 南向驱动，负责电池信息采集（容量/电压/温度/健康/充电状态等）与上报。改动影响电量显示、低电关机、充电策略，须谨慎。

## 工作目录

```bash
OHOS_ROOT=<您的OpenHarmony源码路径>
BATTERY_ROOT=${OHOS_ROOT}/drivers/peripheral/battery
```

## 模块定位与职责

- **部件名**：`@ohos/drivers_peripheral_battery`
- **职责**：实现电池 HDI 接口（`IBatteryInterface`），从 sysfs（`/sys/class/power_supply/...`）读取电池属性，向上对接 battery 服务；实现 `Register/UnRegister/ChangePath` 及 `GetCapacity/GetVoltage/GetTemperature/GetHealthState/GetPluggedType/GetChargeState/GetPresent/GetTechnology/GetTotalEnergy/GetCurrentAverage/GetCurrentNow/GetRemainEnergy` 等。
- **不是什么**：不是 battery 服务（在 `base/powermgr/battery_info` 等上层）；本目录只做 HDI 实现 + sysfs 读取 + 上报线程。
- **风险面**：错误容量/电压致 UI 误导或误触发低电关机；sysfs 路径错误致读不到值（返 -1/默认值）；`ChangePath` 被滥用致读取错误节点；上报线程异常致状态不更新。

## 业务架构

```
┌─────────────────────────────────────────────────────────┐
│          battery_info 服务 (上层 · Proxy 调用方)         │
└─────────────────────────────────────────────────────────┘
                          │ HDI IPC (Proxy)
                          ▼
┌─────────────────────────────────────────────────────────┐
│            HDI 接口层 (drivers/interface/battery)        │
│   IBatteryInterface / IBatteryCallback (IDL v1_0~v2_0)  │
│   生成: libbattery_proxy_1.*.z.so / libbattery_stub_*  │
└─────────────────────────────────────────────────────────┘
                          │ HDI (Stub)
                          ▼
┌─────────────────────────────────────────────────────────┐
│       HDI 实现层 (drivers/peripheral/battery)            │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │ battery_      │ │ battery_     │ │ power_supply_  │ │
│  │ interface_    │ │ thread       │ │ provider       │ │
│  │ impl/driver  │ │ (上报轮询)    │ │ (sysfs 读取)    │ │
│  └──────────────┘ └──────────────┘ └────────────────┘ │
│  ┌──────────────────────────────────────────────────┐  │
│  │ battery_config (节点路径/属性映射 battery_config.json)│  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │ sysfs 读取
                          ▼
┌─────────────────────────────────────────────────────────┐
│  /sys/class/power_supply/battery/{capacity,voltage,    │
│  temp,health,charge_now,current_now,...}                │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                     电池硬件 / Fuel Gauge
```

### 各层职责

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 上层服务 | `base/powermgr/battery_info` 等 | 电量展示/低电关机/充电策略决策（Proxy 调 HDI） |
| HDI 接口层 | `drivers/interface/battery` | IDL 定义，生成 Proxy/Stub/Types |
| HDI 实现层 | `drivers/peripheral/battery/interfaces/hdi_service` | Stub 实现，sysfs 采集 + 周期上报 |
| sysfs/硬件 | `/sys/class/power_supply/battery/*` | 内核 power_supply 节点（Fuel Gauge/充电 IC） |

### 关键流程

**采集与上报**:
```
1. 上层 Register(callback) → Stub 记录 callback
2. battery_thread 周期触发 → power_supply_provider 读 /sys/class/power_supply/battery/*
3. 读到值打包 → callback 上报（或上层主动 Get*）
4. ChangePath(path) 可运行时切换 sysfs 路径（多电池/调试）
```

**Get* 读取**: `GetCapacity/GetVoltage/GetTemperature/...` → `power_supply_provider.cpp` 读对应节点 → 失败返约定默认值（-1）+ 日志。

## 代码路径（关键路径与"去哪找"）

| 任务 | 去哪看 |
| --- | --- |
| HDI 接口实现（Register/UnRegister/ChangePath/各 Get*） | `interfaces/hdi_service/src/battery_interface_impl.cpp` |
| HDI 驱动注册与 HCS 装载 | `interfaces/hdi_service/src/battery_interface_driver.cpp` |
| sysfs power_supply 节点读取 | `interfaces/hdi_service/src/power_supply_provider.cpp` |
| 电池配置（节点路径/属性映射） | `interfaces/hdi_service/src/battery_config.cpp`、`interfaces/hdi_service/profile/battery_config.json` |
| 上报/轮询线程 | `interfaces/hdi_service/src/battery_thread.cpp` |
| 公共工具/类型 | `utils/include/`、`interfaces/include/` |
| HDI 服务测试 | `interfaces/hdi_service/test/` |
| HDI 接口 IDL（上游） | `drivers/interface/battery/`（v1_0/v1_1/v1_2/v2_0） |

## 知识路由（动手前先读对应文档）

### 按任务路由

| 任务场景 | 必读 |
| --- | --- |
| 改 HDI 方法实现/新增属性 | 读 `drivers/interface/battery/` 对应版本 `IBatteryInterface.idl` + `battery_interface_impl.cpp` |
| 改 sysfs 读取 | 读 `power_supply_provider.cpp` + `battery_config.json`（节点路径映射） |
| 改上报线程/轮询周期 | 读 `battery_thread.cpp`；确认周期与节流 |
| 改 HCS/配置 | 读 `profile/battery_config.json` + `BUILD.gn` 的 hcs 安装 |
| 新增电池属性枚举 | 读 `drivers/interface/battery/` 的 `Types.idl`（BatteryHealthState/BatteryPluggedType/BatteryChargeState 等） |

### 按路径路由

| 改动路径 | 风险提示 |
| --- | --- |
| `interfaces/hdi_service/src/*` | HDI 实现层；改动影响所有上层电池读取 |
| `profile/battery_config.json` | 节点路径/属性映射；错误致读不到值或读错节点 |
| `interfaces/hdi_service/test/` | 服务测试；改动需保持 mock 一致 |

### 按术语路由

| 术语 | 含义/风险 | 去哪看 |
| --- | --- | --- |
| power_supply | Linux 电池 sysfs 类；路径错致读不到值 | `power_supply_provider.cpp`、`battery_config.json` |
| ChangePath | 运行时改 sysfs 路径；被滥用致读错节点 | `battery_interface_impl.cpp` |
| 上报线程 | 周期上报电池状态；异常致状态不更新 | `battery_thread.cpp` |
| BatteryHealthState/PluggedType/ChargeState | 电池枚举；新增须同步 IDL | `Types.idl` |
| HCS | HDF 配置集 | `profile/` + `BUILD.gn` |

### 规划声明（动手编辑前必须明确）

先说明：①任务类别（HDI 实现/sysfs 读取/上报线程/配置/测试）；②已读哪些 IDL/文档；③约束与边界；④是否需"Ask before"。

## 约束与边界

### 架构与业务不变量

- HDI 实现层是"读取者+上报者"，不做电池策略决策（决策在 battery 服务）。
- sysfs 节点路径由 `battery_config.json` 统一映射，不得硬编码散落。
- 上报线程与 sysfs 读取解耦：读取失败须返回约定默认值（如 -1）并日志，不得崩溃。
- HDI 方法签名与枚举与 `drivers/interface/battery/` IDL 严格对应。

### Do not

- 不得在 HDI 实现里直接做低电关机/充电策略决策。
- 不得硬编码 sysfs 节点路径（须进 `battery_config.json`）。
- 不得在 sysfs 读取失败时返回伪造值（须返回约定默认值 + 日志）。
- 不得阻塞 HDI 调用做长 IO；读取须有超时/缓存。
- 不得绕过 `Register/UnRegister` 直接调 callback 上报。
- 不得修改 HDI 签名/枚举而不同步 `drivers/interface/battery/` IDL。

### Ask before

- 修改 HDI 方法签名或新增/改枚举（须同步 IDL，属兼容性边界）。
- 修改 sysfs 节点路径映射或上报线程周期。
- 修改 `battery_config.json` 的属性映射。
- 新增/改 HCS 装载或第三方依赖。

### 已知易错点

- 改读取主路径而忽略 `ChangePath` 动态路径分支。
- sysfs 节点路径写死而不进配置 → 跨板级迁移失效。
- 读取失败返回伪造值（如 0）而非 -1 → UI 误显示满电。
- 上报线程异常未兜底 → 状态停更。
- 改 HDI 枚举未同步 IDL → 上层枚举不一致。

## 调试技巧（RK3568）

### 开启电池详细日志

```bash
# battery hilog domain = 0xD002923~0xD002940
hdc shell "hilog -bD -D 0xD002923"
hdc shell "hilog -Q domainoff; hilog -Q pidoff; hilog -p off"
hdc shell "hilog | grep -iE 'battery|power_supply'"
```

### 直接核对 sysfs 值

```bash
hdc shell "cat /sys/class/power_supply/battery/capacity"     # 电量 %
hdc shell "cat /sys/class/power_supply/battery/voltage_now"   # 电压
hdc shell "cat /sys/class/power_supply/battery/temp"          # 温度
hdc shell "cat /sys/class/power_supply/battery/status"        # 充电状态
hdc shell "ls /sys/class/power_supply/"                       # 列出所有 power_supply
```

### 推送调试库

```bash
hdc shell mount -o rw,remount /vendor
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_battery/
hdc file send libbattery_hdi_service.z.so /vendor/lib/
hdc shell killall battery_host 2>/dev/null; sleep 2
hdc shell "ps -A | grep battery"
```

## 部署到设备 (RK3568)

```bash
PID=$(hdc shell "pidof battery_host" | tr -d '\r')
hdc shell "cat /proc/$PID/maps | grep battery_hdi_service"   # 确认加载路径
hdc shell mount -o rw,remount /vendor
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_battery/
hdc file send libbattery_hdi_service.z.so /vendor/lib/
hdc shell killall battery_host 2>/dev/null; sleep 3
```

## 常见问题

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 电量显示固定不变 | 上报线程停更/异常 | 查 `battery_thread.cpp`；查 `ps | grep battery_host` |
| 容量为 -1/异常值 | sysfs 节点路径错/读取失败 | 查 `power_supply_provider.cpp` + `battery_config.json`；核对 `/sys/class/power_supply/battery/*` |
| 充电状态错乱 | `BatteryChargeState` 枚举映射错 | 查 `Types.idl` 枚举与 sysfs `status` 映射 |
| HDI 调用失败 | Stub/IDL 版本不一致 | 确认 `drivers/interface/battery` 版本匹配 |
| 推送后服务起不来 | so 推错分区 | 查 `proc/$PID/maps` |

## 验证闭环

### 最小验证命令（从源码根）

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_battery
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 drivers_peripheral_battery   # 增量
./build.sh --product-name rk3568 --build-target drivers_peripheral_battery_test                       # 单测
代码格式化工具（仓库 prebuilts 下） -i interfaces/hdi_service/src/*.cpp interfaces/hdi_service/include/*.h utils/include/*.h   # 格式化/lint
```

### 按变更类型的最小验证

| 变更类型 | 最小验证 |
| --- | --- |
| 改 HDI 实现 | 编译 + 单测 + 设备上确认 Get* 各属性正确 |
| 改 sysfs 读取 | 编译 + 确认 `/sys/class/power_supply/` 节点存在且值正确 |
| 改上报线程 | 编译 + 长时运行确认状态持续更新 |
| 改配置 | 编译 + 确认 HCS 装载 + 各属性读取回归 |

### Done 定义 / 最终回复 / 回退

同通用要求：行为实现 + 验证已运行或说明无法运行原因 + `git diff` 仅含预期改动 + 错误路径有返回值/日志 + 改接口/配置已检查依赖。环境缺构建链时不伪造，用 `OH 工具链 -fsyntax-only`（带 arm-linux-ohos sysroot/arm-linux-ohos includes）做语法校验并明确为语法级。

## 代码仓依赖

| 路径 | 部件 | 作用 |
| --- | --- | --- |
| `drivers/peripheral/battery` | `drivers_peripheral_battery` | 电池 HDI 实现 |
| `drivers/interface/battery` | `drivers_interface_battery` | 电池 HDI IDL（v1_0/v1_1/v1_2/v2_0） |
| `base/powermgr/battery_info` 等上层 | — | 电池服务（策略/展示） |

## 构建产物

```bash
${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_battery/
# 核心库：libbattery_hdi_service.z.so 等
```
