# Power 驱动 (peripheral) — Agent 工作指南

> 本文件给 AI 编码助手使用。所有在本目录进行的分析、修改、测试、提交说明都应优先遵循这里的约定。把它视为系统级电源管理南向（HDI）驱动的可信边界：休眠/唤醒、RunningLock、系统电源状态对整机可用性影响极大，改动须谨慎。

## 工作目录

```bash
OHOS_ROOT=<您的OpenHarmony源码路径>          # 例：~/ws/ohos
POWER_ROOT=${OHOS_ROOT}/drivers/peripheral/power
```

## 模块定位与职责

- **部件名**：`@ohos/drivers_peripheral_power`
- **职责**：实现 OpenHarmony 电源管理 HDI 南向接口（`IPowerInterface`），向上对接 powermgr 服务，向下控制系统休眠/唤醒、RunningLock（持锁阻止休眠）、休眠配置。
- **不是什么**：不是 powermgr 服务本身（那在 `base/powermgr/powermgr_service`）；本目录只做 HDI 实现 + sysfs/节点交互。不直接处理亮灭屏 UI 逻辑。
- **风险面**：休眠/强制休眠路径误触发会导致设备不可用；RunningLock 计数错误会致设备无法休眠（耗电）或误休眠（业务中断）；sysfs 写入需权限与节点正确性。

## 业务架构

```
┌─────────────────────────────────────────────────────────┐
│                  powermgr_service                        │
│            (上层电源服务 · Proxy 调用方)                  │
└─────────────────────────────────────────────────────────┘
                          │ HDI IPC (Proxy)
                          ▼
┌─────────────────────────────────────────────────────────┐
│              HDI 接口层 (drivers/interface/power)        │
│   IPowerInterface / IPowerHdiCallback /                │
│   IPowerRunningLockCallback  (IDL v1_0~v1_3)            │
│   生成: libpower_proxy_1.*.z.so / libpower_stub_1.*    │
└─────────────────────────────────────────────────────────┘
                          │ HDI (Stub)
                          ▼
┌─────────────────────────────────────────────────────────┐
│        HDI 实现层 (drivers/peripheral/power)             │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │ power_        │ │ hibernate    │ │ system_        │ │
│  │ interface_    │ │ (休眠/唤醒)   │ │ operation      │ │
│  │ impl/driver  │ │              │ │ (sysfs 交互)    │ │
│  └──────────────┘ └──────────────┘ └────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │ running_lock_│ │ running_lock_│ │ power_config   │ │
│  │ impl         │ │ counter/     │ │ (状态机/配置)   │ │
│  │ (持锁/释放)   │ │ timer_handler│ │                │ │
│  └──────────────┘ └──────────────┘ └────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │ sysfs 写入/读取
                          ▼
┌─────────────────────────────────────────────────────────┐
│   /sys/power/state  /sys/power/wake_lock  /sys/power/   │
│   wake_unlock  /sys/power/wakeup_count  /sys/power/      │
│   resume  /sys/hibernate/resume                          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                     Kernel / 硬件
```

### 各层职责

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 上层服务 | `base/powermgr/powermgr_service` | 状态机决策（何时休眠/亮灭屏），通过 Proxy 调 HDI |
| HDI 接口层 | `drivers/interface/power` | IDL 定义，生成 Proxy/Stub/Types |
| HDI 实现层 | `drivers/peripheral/power/interfaces/hdi_service` | Stub 实现，执行休眠/RunningLock/sysfs 交互 |
| sysfs/硬件 | `/sys/power/*` | 内核电源节点 |

### 关键流程

**休眠流程**:
```
1. powermgr 决策休眠 → Proxy::StartSuspend()
2. Stub power_interface_impl.cpp:StartSuspend()
3. RunningLock counter 检查无持锁 → system_operation 写 /sys/power/state
4. 内核进入休眠
```

**RunningLock 持锁防休眠**:
```
1. 应用持锁 → Proxy::SuspendBlock(name)
2. Stub running_lock_impl.cpp → counter +1
3. system_operation 写 /sys/power/wake_lock
4. 设备保持唤醒；释放时写 wake_unlock，counter -1
```

**强制休眠**: `ForceSuspend()` → 绕过 RunningLock 检查直接写 `/sys/power/state`（危险，仅特定场景）。

## 代码路径（关键路径与"去哪找"）

| 任务 | 去哪看 |
| --- | --- |
| HDI 接口实现（RegisterCallback/StartSuspend/StopSuspend/ForceSuspend/SuspendBlock/SuspendUnblock/PowerDump） | `interfaces/hdi_service/src/power_interface_impl.cpp` |
| HDI 驱动注册与 HCS 装载 | `interfaces/hdi_service/src/power_interface_driver.cpp` |
| 休眠实现 | `interfaces/hdi_service/src/hibernate.cpp` |
| RunningLock 持锁/释放、计数 | `interfaces/hdi_service/src/running_lock_impl.cpp`、`running_lock_counter.cpp`、`running_lock_timer_handler.cpp` |
| 系统电源操作（sysfs 交互） | `interfaces/hdi_service/src/system_operation.cpp` |
| 电源配置（休眠状态机/默认值） | `interfaces/hdi_service/src/power_config.cpp`、`interfaces/hdi_service/profile/power_config.json` |
| 公共工具/类型 | `utils/include/` |
| init 启动参数 | `etc/para/` |
| 单元测试 | `test/unittest/src/` |
| Fuzz 测试 | `test/fuzztest/{powerhdi_fuzzer,powerhdistub_fuzzer,power_fuzzer}/` |
| HDI 接口 IDL 定义（上游） | `drivers/interface/power/` |

## 知识路由（动手前先读对应文档）

### 按任务路由

| 任务场景 | 必读 |
| --- | --- |
| 修改 HDI 方法实现/新增能力 | 读 `drivers/interface/power/` 对应版本的 `IPowerInterface.idl` + 本目录 `power_interface_impl.cpp` |
| 修改休眠/唤醒流程 | 读 `hibernate.cpp`、`system_operation.cpp`；确认 sysfs 节点路径与 power_config.json 状态机 |
| 修改 RunningLock | 读 `running_lock_impl.cpp` + `running_lock_counter.cpp` + `running_lock_timer_handler.cpp`；确认持锁计数与超时回收 |
| 修改 HCS/配置 | 读 `interfaces/hdi_service/profile/power_config.json` + `BUILD.gn` 的 hcs 安装目标 |
| 新增/修改 init 参数 | 读 `etc/para/`，确认参数名与 powermgr 侧引用一致 |
| 测试编写/定位 | 读 `test/unittest` 与 `test/fuzztest` 的现有 mock 结构 |

### 按路径路由

| 改动路径 | 风险提示 |
| --- | --- |
| `interfaces/hdi_service/src/*` | HDI 实现层；改动影响所有上层电源调用，必须回归休眠/唤醒 |
| `interfaces/hdi_service/profile/power_config.json` | 休眠状态机/节点配置；错误配置致设备无法唤醒 |
| `etc/para/` | init 参数；命名/默认值变更影响启动行为 |

### 按术语路由

| 术语 | 含义/风险 | 去哪看 |
| --- | --- | --- |
| RunningLock | 持锁阻止系统休眠；计数错误致耗电或误休眠 | `running_lock_*.cpp` |
| Suspend / ForceSuspend | 系统休眠/强制休眠；误触发致设备不可用 | `hibernate.cpp`、`system_operation.cpp` |
| SuspendBlock/Unblock | 内核 wakelock 阻塞/释放 | `system_operation.cpp`（sysfs） |
| HCS | HDF 配置集，驱动装载依赖 | `profile/` + `BUILD.gn` |
| HDI | Hardware Device Interface，电源南向接口 | `drivers/interface/power/` 的 IDL |
| sysfs 节点 | `/sys/power/...` 等；写入需权限 | `system_operation.cpp` |

### 规划声明（动手编辑前必须明确）

在改任何文件前，先在回复中说明：①任务属于哪类（HDI 实现/休眠流程/RunningLock/配置/测试）；②已读哪些文档/IDL；③发现的约束或边界；④是否需要走"Ask before"流程。

## 约束与边界

### 架构与业务不变量

- HDI 实现层不得绕过 powermgr 服务的电源状态机；本目录是"执行者"，状态决策由上层。
- RunningLock 计数必须严格配对（持锁+1/释放-1），计数错配会致设备无法休眠或误休眠。
- sysfs 节点路径与写入格式由 `power_config.json` / `system_operation.cpp` 约定，不得硬编码随意路径。
- HDI 方法签名与错误码与 `drivers/interface/power/` IDL 一一对应，不得在本目录单边改签名。

### Do not（不得）

- 不得在 HDI 实现里直接做亮灭屏 UI 决策；只执行上层下发的休眠/唤醒。
- 不得随意写 sysfs 节点做"调试用"副作用，尤其 `/sys/power/state`、`wake_lock`、`wake_unlock`。
- 不得修改 `power_config.json` 的状态机定义而不回归休眠/唤醒路径。
- 不得删除/合并 RunningLock 计数分支（成功/失败/超时回收）中的任一。
- 不得引入新的 sysfs 节点访问而不走配置与权限校验。
- 不得绕过 `RegisterCallback` 的回调注册路径直接调用 callback。

### Ask before（须用户确认）

- 修改 HDI 方法签名或错误码（属接口兼容性边界，需同步改 `drivers/interface/power/` IDL）。
- 修改 sysfs 节点路径或休眠状态机（`power_config.json`/`system_operation.cpp`）。
- 修改 RunningLock 计数语义或超时回收策略。
- 新增 init 参数或改默认值（`etc/para/`）。
- 新增/修改 HCS 装载配置。
- 新增第三方依赖。

### 已知易错点

- 改休眠主路径而忽略 ForceSuspend/超时回收分支。
- RunningLock 计数在异常路径漏释放 → 设备永不休眠。
- sysfs 节点路径写死而不进配置 → 跨板级迁移失效。
- HDI 方法只改实现未同步 IDL 版本 → 上层编译/运行不一致。
- 改 HCS 装载名未同步 `BUILD.gn` 与 `power_interface_driver.cpp`。

## 调试技巧（RK3568）

### 开启电源详细日志

```bash
# power hilog domain = 0xD002511
hdc shell "hilog -bD -D 0xD002511"     # 开 power 域 DEBUG
hdc shell "hilog -Q domainoff"          # 关域流控
hdc shell "hilog -Q pidoff"             # 关 PID 流控
hdc shell "hilog -p off"                # 关隐私打印
hdc shell "hilog | grep -i power"       # 查看电源日志
```

### 验证休眠/唤醒

```bash
# 查看当前 RunningLock 计数与持锁列表
hdc shell "hidumper -s power_host -a '-h'" 2>/dev/null
# 直接读内核 wakelock
hdc shell "cat /sys/power/wake_lock"
hdc shell "cat /sys/power/wake_unlock"
# 模拟休眠（谨慎！致设备不可交互）
hdc shell "echo mem > /sys/power/state"
```

### 推送调试库

```bash
hdc shell mount -o rw,remount /vendor   # 或 /system，先查 maps 确认实际加载路径
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_power/
hdc file send libpower_hdi_service.z.so /vendor/lib/
hdc shell killall power_host 2>/dev/null; sleep 2
hdc shell "ps -A | grep power"
```

## 部署到设备 (RK3568)

```bash
# 1. 确定加载路径（先查 power_host 进程 maps）
PID=$(hdc shell "pidof power_host" | tr -d '\r')
hdc shell "cat /proc/$PID/maps | grep power_hdi_service"   # 确认 /vendor/lib 还是 /system/lib

# 2. 推送
hdc shell mount -o rw,remount /vendor
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_power/
hdc file send libpower_hdi_service.z.so /vendor/lib/

# 3. 重启电源服务
hdc shell killall power_host 2>/dev/null; sleep 3
hdc shell "ps -A | grep power"
```

## 常见问题

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 设备永不休眠（耗电） | RunningLock 计数漏释放 | 查 `cat /sys/power/wake_lock` 是否常驻；查 `running_lock_counter.cpp` 配对 |
| 设备误休眠（业务中断） | RunningLock 误释放/计数减穿 | 查 counter 是否变负；查持锁超时回收分支 |
| 休眠后无法唤醒 | `power_config.json` 状态机/节点错 | 查 `hibernate.cpp` + `power_config.json`；确认 `/sys/power/wakeup_count` |
| HDI 调用报错 | Stub 与 IDL 版本不一致 | 确认 `drivers/interface/power` 版本与 Stub 实现匹配 |
| 推送后服务起不来 | so 推错分区 | 查 `proc/$PID/maps` 确认实际加载路径 |

## 验证闭环

### 最小验证命令（从源码根执行）

```bash
cd ${OHOS_ROOT}
# 编译 power 驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_power
# 快速增量（仅改源码）
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 drivers_peripheral_power
# 单元测试
./build.sh --product-name rk3568 --build-target drivers_peripheral_power_test
# fuzz 测试目标
./build.sh --product-name rk3568 --build-target powerhdi_fuzzer
# 格式化/lint（改 .cpp/.h 后必跑）
代码格式化工具（仓库 prebuilts 下） -i interfaces/hdi_service/src/*.cpp interfaces/hdi_service/include/*.h utils/include/*.h
```

### 按变更类型的最小验证

| 变更类型 | 最小验证 |
| --- | --- |
| 改 HDI 实现（hdi_service/src） | 编译通过 + 单元测试 + 手动回归休眠/唤醒 |
| 改 RunningLock | 编译通过 + running_lock 单测 + 长时运行确认计数平衡 |
| 改配置（power_config.json/HCS） | 编译通过 + 确认 HCS 装载成功 + 休眠/唤醒回归 |
| 改 sysfs 节点路径 | 编译通过 + 设备上确认节点存在且可写 |

### Done 定义

任务完成须同时满足：①行为已实现；②编译+相关单测已运行或已说明无法运行原因；③`git diff` 仅含预期改动；④错误路径有清晰返回值/日志；⑤改接口/配置/构建时已检查依赖与装载。

### 最终回复须包含

- 改了哪些文件；②解决了什么行为问题；③运行了哪些验证及结果；④哪些验证因环境限制未运行及残留风险。

### 验证无法运行时的回退

若环境缺 OHOS 构建链（`hb`/ninja/产品配置），不得伪造构建结果：明确写出未能运行的命令与原因，至少用 `OH 工具链 -fsyntax-only`（带arm-linux-ohos sysroot/arm-linux-ohos includes）对改动文件做语法校验，并说明这是语法级而非链接级验证。

## 代码仓依赖

| 路径 | 部件 | 作用 |
| --- | --- | --- |
| `drivers/peripheral/power` | `drivers_peripheral_power` | 电源 HDI 实现 |
| `drivers/interface/power` | `drivers_interface_power` | 电源 HDI IDL（v1_0~v1_3） |
| `base/powermgr/powermgr_service` | — | 上层电源服务（状态决策方） |

## 构建产物

```bash
${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_power/
# 核心库：libpower_hdi_service.z.so 等
```
