# Thermal 驱动 (peripheral) — Agent 工作指南

> 给 AI 编码助手使用。本目录是 OpenHarmony 温控 HDI 南向驱动，负责温升采集、CPU/GPU 限频、充电限流等温控降频（mitigation）执行。改动影响设备温升安全与性能，须谨慎。

## 工作目录

```bash
OHOS_ROOT=<您的OpenHarmony源码路径>
THERMAL_ROOT=${OHOS_ROOT}/drivers/peripheral/thermal
```

## 模块定位与职责

- **部件名**：`@ohos/drivers_peripheral_thermal`
- **职责**：实现温控 HDI 接口（`IThermalInterface`），向上对接 thermal 服务，向下采集温区（thermal zone）数据并执行限频/限流（`SetCpuFreq`/`SetGpuFreq`/`SetBatteryCurrent`/`GetThermalZoneInfo`/`Register`/`Unregister`）。
- **不是什么**：不是 thermal 服务（在 `base/powermgr/thermal_manager` 等上层，做温控策略决策）；本目录是"采集者+执行者"。不直接做 UI。
- **风险面**：限频过度致性能骤降或限频不足致设备过热损坏；温区读取错误致策略误判；限频路径误写 sysfs 致异常；定时器/降频线程异常致温控失效。

## 业务架构

```
┌─────────────────────────────────────────────────────────┐
│      thermal_manager 服务 (上层 · 策略决策 · Proxy)      │
└─────────────────────────────────────────────────────────┘
                          │ HDI IPC (Proxy)
                          ▼
┌─────────────────────────────────────────────────────────┐
│           HDI 接口层 (drivers/interface/thermal)         │
│   IThermalInterface / IThermalCallback / IFanCallback   │
│   (IDL v1_0/v1_1)  生成 proxy/stub/types                │
└─────────────────────────────────────────────────────────┘
                          │ HDI (Stub)
                          ▼
┌─────────────────────────────────────────────────────────┐
│       HDI 实现层 (drivers/peripheral/thermal)            │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │ thermal_      │ │ thermal_     │ │ thermal_device_│ │
│  │ interface_    │ │ hdf_timer    │ │ mitigation     │ │
│  │ impl/driver  │ │ (周期采集)    │ │ (限频执行)      │ │
│  └──────────────┘ └──────────────┘ └────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │thermal_hdf_ │ │base/sensor/  │ │ thermal_dfx    │ │
│  │config/utils │ │isolate_info_ │ │ (温控打点)      │ │
│  │(配置/读取)   │ │config        │ │                │ │
│  └──────────────┘ └──────────────┘ └────────────────┘ │
│  profile: thermal_hdi_config.xml (温区/限频节点配置)    │
└─────────────────────────────────────────────────────────┘
                          │ sysfs 读写
                          ▼
┌─────────────────────────────────────────────────────────┐
│ /sys/class/thermal/thermal_zone* (温区温度)             │
│ /sys/class/hwmon/*/temp          (传感器温度)            │
│ /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq   │
│ /sys/class/power_supply/battery/input_current_limited   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
              SoC / 电池 / 风扇 硬件
```

### 各层职责

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 上层服务 | `base/powermgr/thermal_manager` | 温控策略（何时降到何档），Proxy 调 HDI |
| HDI 接口层 | `drivers/interface/thermal` | IDL 定义，生成 Proxy/Stub/Types |
| HDI 实现层 | `drivers/peripheral/thermal/interfaces/hdi_service` | Stub 实现，温区采集 + 限频执行 |
| sysfs/硬件 | `/sys/class/thermal/*`、`/sys/devices/system/cpu/*/cpufreq/*` | 内核温控/cpufreq 节点 |

### 关键流程

**温区采集**:
```
1. thermal_hdf_timer 周期触发 → thermal_hdf_utils 读 /sys/class/thermal/thermal_zone*
2. 打包温区信息 → 上层 Register(callback) 上报 / GetThermalZoneInfo 主动拉取
3. 采集失败返约定默认值 + 日志，不崩溃
```

**限频执行（mitigation）**:
```
1. 上层策略决策 → Proxy::SetCpuFreq(freq) / SetGpuFreq / SetBatteryCurrent
2. Stub thermal_device_mitigation.cpp → 限频值经上下限保护 → 写 sysfs
   - CPU: /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq
   - 充电限流: /sys/class/power_supply/battery/input_current_limited
3. 越界限频值被 clamp 到上下限，不直写越界值
```

## 代码路径（关键路径与"去哪找"）

| 任务 | 去哪看 |
| --- | --- |
| HDI 接口实现（SetCpuFreq/SetGpuFreq/SetBatteryCurrent/GetThermalZoneInfo/Register/Unregister） | `interfaces/hdi_service/src/thermal_interface_impl.cpp` |
| HDI 驱动注册与 HCS 装载 | `interfaces/hdi_service/src/thermal_interface_driver.cpp` |
| 降频执行（mitigation） | `interfaces/hdi_service/src/thermal_device_mitigation.cpp` |
| 温区/HDF 配置解析 | `interfaces/hdi_service/src/thermal_hdf_config.cpp`、`profile/thermal_hdi_config.xml` |
| 定时器/周期采集 | `interfaces/hdi_service/src/thermal_hdf_timer.cpp` |
| 温区工具/读取 | `interfaces/hdi_service/src/thermal_hdf_utils.cpp` |
| 基础/sensor/isolate 信息配置 | `interfaces/hdi_service/src/base_info_config.cpp`、`sensor_info_config.cpp`、`isolate_info_config.cpp` |
| DFX | `interfaces/hdi_service/src/thermal_dfx.cpp` |
| 单元测试 | `test/unittest/` |
| Fuzz | `test/fuzztest/thermalhdistub_fuzzer/` |
| HDI 接口 IDL（上游） | `drivers/interface/thermal/`（v1_0/v1_1） |

## 知识路由（动手前先读对应文档）

### 按任务路由

| 任务场景 | 必读 |
| --- | --- |
| 改 HDI 方法实现/新增能力 | 读 `drivers/interface/thermal/` 对应版本 `IThermalInterface.idl` + `thermal_interface_impl.cpp` |
| 改限频/限流执行 | 读 `thermal_device_mitigation.cpp`；确认 sysfs 节点路径与上下限 |
| 改温区采集/解析 | 读 `thermal_hdf_config.cpp`、`thermal_hdf_utils.cpp`、`profile/thermal_hdi_config.xml` |
| 改定时器/周期 | 读 `thermal_hdf_timer.cpp`；确认周期与节流 |
| 改 base/sensor/isolate 信息 | 读 `base_info_config.cpp`/`sensor_info_config.cpp`/`isolate_info_config.cpp` |
| 改 DFX | 读 `thermal_dfx.cpp`；保持温控事件打点风格一致 |
| 测试 | 读 `test/unittest`、`test/fuzztest` |

### 按路径路由

| 改动路径 | 风险提示 |
| --- | --- |
| `interfaces/hdi_service/src/*` | HDI 实现层；改动影响温控采集与降频执行 |
| `profile/thermal_hdi_config.xml` | 温区/限频节点配置；错误致采集失效或误降频 |
| `thermal_dfx.cpp` | 温控 DFX；改动须保持打点与上层归因一致 |

### 按术语路由

| 术语 | 含义/风险 | 去哪看 |
| --- | --- | --- |
| mitigation | 温控降频/限流执行；过度致性能骤降，不足致过热 | `thermal_device_mitigation.cpp` |
| thermal zone | Linux 温区；读取错致策略误判 | `thermal_hdf_utils.cpp`、`thermal_hdf_config.cpp` |
| SetCpuFreq/SetGpuFreq/SetBatteryCurrent | 限频/限流 sysfs 写入；路径错致异常 | `thermal_device_mitigation.cpp` |
| HDF 定时器 | 周期采集；异常致温控停更 | `thermal_hdf_timer.cpp` |
| HCS/XML | 温控配置 | `profile/thermal_hdi_config.xml` |

### 规划声明（动手编辑前必须明确）

先说明：①任务类别（HDI 实现/降频执行/采集/配置/定时器/DFX/测试）；②已读哪些 IDL/文档；③约束与边界；④是否需"Ask before"。

## 约束与边界

### 架构与业务不变量

- 本目录是"采集者+执行者"，温控策略（何时降频到何档）由上层 thermal 服务决策，HDI 只执行。
- 限频 sysfs 节点路径由 `thermal_hdi_config.xml`/`thermal_device_mitigation.cpp` 约定，不得硬编码。
- 限频值须有上下限保护（不得直接写越界值到 sysfs）。
- 定时器与采集解耦：采集失败须返回约定默认值并日志，不得崩溃。
- HDI 方法签名与 `drivers/interface/thermal/` IDL 严格对应。

### Do not

- 不得在 HDI 实现里直接做温控策略决策（阈值/档位）。
- 不得硬编码限频 sysfs 路径（须进配置）。
- 不得把越界限频值直接写 sysfs（须上下限保护）。
- 不得阻塞 HDI 调用做长 IO。
- 不得绕过 `Register/Unregister` 直接调 callback。
- 不得改 HDI 签名/枚举而不同步 `drivers/interface/thermal/` IDL。
- 不得改 DFX 打点而不保持与上层温控归因一致。

### Ask before

- 修改 HDI 方法签名或枚举（须同步 IDL，兼容性边界）。
- 修改限频 sysfs 节点路径或上下限保护策略。
- 修改 `thermal_hdi_config.xml` 温区/限频配置。
- 修改定时器周期。
- 新增/改 HCS 装载或第三方依赖。

### 已知易错点

- 改降频主路径而忽略上下限保护/异常路径。
- 限频 sysfs 路径写死而不进配置 → 跨板级迁移失效。
- 定时器异常未兜底 → 温控停更致过热。
- 温区读取失败返回伪造值 → 策略误判。
- 改 DFX 打点未保持与上层归因一致 → 温控故障难定位。
- 改 HDI 枚举未同步 IDL。

## 调试技巧（RK3568）

### 开启温控详细日志

```bash
# thermal hilog domain = 0xD002943
hdc shell "hilog -bD -D 0xD002943"
hdc shell "hilog -Q domainoff; hilog -Q pidoff; hilog -p off"
hdc shell "hilog | grep -iE 'thermal|mitigation'"
```

### 直接核对温区/限频 sysfs

```bash
hdc shell "ls /sys/class/thermal/"                       # 列温区
hdc shell "cat /sys/class/thermal/thermal_zone*/temp"     # 各温区温度（×0.001 ℃）
hdc shell "cat /sys/class/thermal/thermal_zone*/type"     # 温区类型
hdc shell "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"  # CPU 限频上限
hdc shell "cat /sys/class/power_supply/battery/input_current_limited" # 充电限流
```

### 推送调试库

```bash
hdc shell mount -o rw,remount /vendor
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_thermal/
hdc file send libthermal_hdi_service.z.so /vendor/lib/
hdc shell killall thermal_host 2>/dev/null; sleep 2
hdc shell "ps -A | grep thermal"
```

## 部署到设备 (RK3568)

```bash
PID=$(hdc shell "pidof thermal_host" | tr -d '\r')
hdc shell "cat /proc/$PID/maps | grep thermal_hdi_service"
hdc shell mount -o rw,remount /vendor
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_thermal/
hdc file send libthermal_hdi_service.z.so /vendor/lib/
hdc shell killall thermal_host 2>/dev/null; sleep 3
```

## 常见问题

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 设备过热不降频 | 限频未执行/上下限 clamp 错 | 查 `thermal_device_mitigation.cpp`；核对 cpufreq/input_current_limited 节点可写 |
| 性能骤降不恢复 | 限频上限未回升/策略未解除 | 查上层 thermal_manager 策略 + `SetCpuFreq` 调用 |
| 温区数据恒定/异常 | 采集线程停更/温区路径错 | 查 `thermal_hdf_timer.cpp` + `thermal_hdf_config.cpp`；核对 `/sys/class/thermal/*` |
| 限频写 sysfs 失败 | 节点路径/权限错 | 查 `thermal_hdi_config.xml` 节点配置 + 权限 |
| HDI 调用失败 | Stub/IDL 版本不一致 | 确认 `drivers/interface/thermal` 版本匹配 |
| 推送后服务起不来 | so 推错分区 | 查 `proc/$PID/maps` |

## 验证闭环

### 最小验证命令（从源码根）

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_thermal
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 drivers_peripheral_thermal   # 增量
./build.sh --product-name rk3568 --build-target drivers_peripheral_thermal_test                       # 单测
./build.sh --product-name rk3568 --build-target thermalhdistub_fuzzer                                 # fuzz
代码格式化工具（仓库 prebuilts 下） -i interfaces/hdi_service/src/*.cpp interfaces/hdi_service/include/*.h   # 格式化/lint
```

### 按变更类型的最小验证

| 变更类型 | 最小验证 |
| --- | --- |
| 改 HDI 实现 | 编译 + 单测 + 设备上确认限频/采集正确 |
| 改降频执行 | 编译 + 确认 sysfs 限频节点可写且值在上下限 |
| 改采集/配置 | 编译 + 确认温区数据正确 + 限频回归 |
| 改定时器 | 编译 + 长时运行确认持续采集 |
| 改 DFX | 编译 + 确认打点与上层归因一致 |

### Done 定义 / 最终回复 / 回退

同通用要求：行为实现 + 验证已运行或说明无法运行原因 + `git diff` 仅含预期改动 + 错误路径有返回值/日志 + 改接口/配置已检查依赖。环境缺构建链时不伪造，用 `OH 工具链 -fsyntax-only`（带 arm-linux-ohos sysroot/arm-linux-ohos includes）做语法校验并明确为语法级。

## 代码仓依赖

| 路径 | 部件 | 作用 |
| --- | --- | --- |
| `drivers/peripheral/thermal` | `drivers_peripheral_thermal` | 温控 HDI 实现 |
| `drivers/interface/thermal` | `drivers_interface_thermal` | 温控 HDI IDL（v1_0/v1_1） |
| `base/powermgr/thermal_manager` 等上层 | — | 温控服务（策略决策） |

## 构建产物

```bash
${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_thermal/
# 核心库：libthermal_hdi_service.z.so 等
```
