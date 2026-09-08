# AGENTS.md - OpenHarmony 振动 HDI 外设驱动（Drivers Peripheral Vibrator）

## 1. 代码地图

本仓库实现 OpenHarmony 振动 HDI 外设驱动，提供振动控制（单次、持续、复合效果）、HD 触觉反馈（Haptic）、基于会话的振动控制及热插拔振动器支持。核心架构边界是**上层 miscservices 和音频框架通过 `drivers/interface/vibrator` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商振动器硬件**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/vibrator/`：HDI IDL 接口定义（v2_0），由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `chipset/` 下各芯片厂商驱动（drv2605l/linear）：由芯片厂商维护

### 嵌套指引

本仓目前无嵌套 AGENTS.md / CLAUDE.md / rules / skills 文件。以下子目录可按需新建嵌套 AGENTS.md：

- `hdi_service_2.0/`：当前活跃 HDI 服务（v2_0），可新建 `hdi_service_2.0/AGENTS.md` 聚焦服务 stub、HD 触觉、会话振动、热插拔
- `hdi_impl/`：HDI 实现层，可新建 `hdi_impl/AGENTS.md` 聚焦振动操作核心逻辑
- `hal/`：振动控制器，可新建 `hal/AGENTS.md` 聚焦 ioctl 命令、内置效果映射表
- `chipset/drv2605l/`：TI DRV2605L 触觉驱动，可新建 `chipset/drv2605l/AGENTS.md` 聚焦芯片适配
- `chipset/linear/`：通用线性谐振致动器，可新建 `chipset/linear/AGENTS.md` 聚焦 LRA 适配

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `vibrator_if.h`（VibratorInterface 结构体：StartOnce、Start、Stop、GetVibratorInfo、EnableVibratorModulation、EnableCompositeEffect、GetEffectInfo、IsVibratorRunning、PlayHapticPattern、GetHapticCapacity、GetHapticStartUpTime）、`vibrator_type.h`（VibratorMode、EffectType、VibratorInfo、TimeEffect、PrimitiveEffect、CompositeEffect、HapticPaket、HapticCapacity、CurvePoint、HapticEvent）
- `interfaces/v1_1/`：VDI 接口头文件，含 `ivibrator_interface_vdi.h`、`ivibrator_type_vdi.h`
- `hdi_service/`：旧版 HDI 服务实现（v1_0 时代）
- `hdi_service_2.0/`：**当前活跃** HDI 服务实现（v2_0）
- `hdi_impl/`：HDI 实现层（`vibrator_interface_impl.cpp/h`，振动操作逻辑）
- `hal/`：硬件抽象层（`vibrator_controller.h`：VibratorDevice 结构体、ioctl 命令 START_ONCE/START_EFFECT/STOP/GET_INFO/ENABLE_MODULATION_PARAMETER/IS_VIBRATOR_RUNNING、内置效果映射表 haptic.clock.timer 等）
- `chipset/`：厂商振动器芯片驱动：
  - `chipset/drv2605l/`：TI DRV2605L 触觉驱动
  - `chipset/linear/`：通用线性谐振致动器驱动
- `utils/`：工具函数（`vibrator_uhdf_log.h`）
- `test/`：`unittest/`、`fuzztest/`（vibrator_fuzzer、vibratorstart_fuzzer、vibratorstartonce_fuzzer、vibratorplaypatternbysessionid_fuzzer、vibratorgethapticcapacity_fuzzer、stopvibratebysessionid_fuzzer、vibratorplayhapticpattern_fuzzer）、`benchmarktest/`、`performance/`
- `vibrator.gni`：4 个特性开关

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 振动控制逻辑 | `hdi_impl/` + `hal/` + `interfaces/include/vibrator_if.h` |
| HD 触觉反馈 | `interfaces/include/vibrator_type.h` 中 HapticPaket/HapticEvent + `hdi_service_2.0/` |
| 会话振动 | `drivers/interface/vibrator/v2_0/IVibratorInterface.idl` 中 PlayPatternBySessionId/PlayPackageBySession/StopVibrateBySessionId |
| 热插拔支持 | `drivers/interface/vibrator/v2_0/IVibratorPlugCallback.idl` + `hdi_service_2.0/` |
| HAL 适配 | `hal/` + `hal/include/vibrator_controller.h` |
| 芯片驱动 | `chipset/drv2605l/` 或 `chipset/linear/` |
| 内置效果 | `hal/include/vibrator_controller.h` 中内置效果映射表 |
| 特性开关 | `vibrator.gni` 的 `declare_args()` 段 |
| 测试 | `test/unittest/` + `test/fuzztest/`（7 个） |

### 架构分层

```
上层（miscservices 振动服务 / 音频框架触觉同步）
  └─ proxy（由 drivers/interface/vibrator IDL 生成）
      ↓ IPC
HDI Service
  ├─ hdi_service_2.0/（当前活跃，v2_0）
  └─ hdi_service/（旧版，v1_0 时代）
      ↓
HDI Impl（hdi_impl/vibrator_interface_impl.cpp）
      ↓
HAL（hal/）— 振动控制器，ioctl 命令 + 内置效果映射
      ↓
Chipset Drivers（chipset/）— 厂商振动器芯片
  ├─ drv2605l/（TI DRV2605L）
  └─ linear/（通用线性谐振致动器）
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改振动接口 | `interfaces/include/` → `hdi_service_2.0/` → `drivers/interface/vibrator` IDL |
| HD 触觉反馈 | `hdi_impl/` + `interfaces/include/vibrator_type.h`（HapticPaket/HapticEvent） |
| 会话振动 | `hdi_service_2.0/` + `drivers/interface/vibrator/v2_0/IVibratorInterface.idl` |
| 热插拔支持 | `hdi_service_2.0/` + `drivers/interface/vibrator/v2_0/IVibratorPlugCallback.idl` |
| 复合效果 | `interfaces/include/vibrator_type.h`（CompositeEffect/TimeEffect/PrimitiveEffect） |
| HAL 适配 | `hal/` + `hal/include/vibrator_controller.h` |
| 新增芯片驱动 | `chipset/` + `hal/include/vibrator_controller.h` |
| 内置效果 | `hal/include/vibrator_controller.h` 中效果映射表 |
| 特性开关变更 | `vibrator.gni` + `bundle.json` |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/benchmarktest/` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API，变更需同步 `hdi_service_2.0/` 和下游 miscservices |
| `interfaces/v1_1/` | VDI 接口，版本化 |
| `hdi_service_2.0/` | **当前活跃服务**，对应 `drivers/interface/vibrator/v2_0/` IDL |
| `hdi_service/` | **旧版服务**（v1_0），非活跃 |
| `hdi_impl/` | HDI 实现层，振动操作核心逻辑 |
| `hal/` | 振动控制器（ioctl），厂商适配 |
| `chipset/` | 厂商振动器芯片驱动 |
| `vibrator.gni` | 4 个特性开关，变更需同步 `bundle.json` |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| VibratorMode | 振动模式（ONCE=0, PRESET=1, HDHAPTIC=2） | `interfaces/include/vibrator_type.h` |
| HDHAPTIC | HD 触觉模式，v2_0 新增 | `interfaces/include/vibrator_type.h` |
| HapticPaket | 触觉数据包，HD 触觉反馈的数据单元 | `interfaces/include/vibrator_type.h` |
| HapticEvent | 触觉事件 | `interfaces/include/vibrator_type.h` |
| CompositeEffect | 复合效果（时间+原始效果组合） | `interfaces/include/vibrator_type.h` |
| CurvePoint | 振动曲线点 | `interfaces/include/vibrator_type.h` |
| SessionId | 会话 ID，用于音频框架触觉同步 | `drivers/interface/vibrator/v2_0/IVibratorInterface.idl` |
| PlugCallback | 热插拔回调 | `drivers/interface/vibrator/v2_0/IVibratorPlugCallback.idl` |
| DRV2605L | TI DRV2605L 触觉驱动芯片 | `chipset/drv2605l/` |
| Linear | 通用线性谐振致动器 | `chipset/linear/` |
| TV Flag | TV 平台标志 | `vibrator.gni` 中 `drivers_peripheral_vibrator_feature_tv_flag` |

### 在计划阶段，必须声明

- **任务分类**（如：振动接口变更 / HD 触觉反馈 / 会话振动 / 热插拔支持 / HAL 适配 / 芯片驱动 / 内置效果 / 特性开关变更 / 测试修改）
- **目标服务版本**（hdi_service_2.0 当前活跃 / hdi_service 旧版），明确是否为活跃构建
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、v2_0 合并特性、会话振动与音频框架时序依赖、hilog_lite 依赖、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `hdi_service_2.0/` 实现 + `drivers/interface/vibrator` IDL + 下游 miscservices
  - 会话振动变更 → 评估与音频框架的时序依赖
  - 特性开关变更 → 同步 `vibrator.gni` + `bundle.json` features 列表
  - 新增芯片驱动 → 放在 `chipset/` 目录
  - 内置效果变更 → 评估 `hal/include/vibrator_controller.h` 中效果映射表对系统默认振动行为的影响

## 3. 约束边界

### 架构不变量

- **hdi_service_2.0 是当前活跃服务**：新功能在 v2_0 上开发，hdi_service/ 是旧版
- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/vibrator`
- **v2_0 是"大版本"**：合并了 v1_0-v1_3 所有功能并新增 v2_0 特性
- **HD 触觉和会话振动是 v2_0 独有**：旧版本不支持
- **HAL 层通过 ioctl + 内置效果映射表对接硬件**

### 禁止事项

- **不要直接修改 `drivers/interface/vibrator` 的 IDL 文件**
- **不要在 `hal/` 中写框架业务逻辑**
- **不要降级使用旧版 `hdi_service/`**：新功能应在 `hdi_service_2.0/` 开发
- **不要在 v1_x 版本中引入 v2_0 特有功能**
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/vibrator` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在 `hal/` 中写框架业务逻辑②修改 IDL 文件而非通过接口评审③降级使用旧版 `hdi_service/`④会话振动变更不评估音频框架时序依赖⑤v2_0 合并特性修改遗漏旧方法⑥特性开关翻转不同步 `bundle.json`

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 miscservices 和音频框架兼容性影响
- **切换特性开关默认值**：确认 vibrator.gni 中 tv_flag/community 开关翻转的影响
- **修改会话振动方法**：确认与音频框架触觉同步的时序依赖
- **修改内置效果映射表**：确认对系统默认振动行为的影响

### 需确认后再修改

- **公共 API 头文件签名变更**：需评估下游 miscservices 和音频框架兼容性
- **内置效果映射表变更**：`hal/include/vibrator_controller.h` 中的效果映射影响系统默认振动行为
- **特性开关默认值翻转**：特别是 `tv_flag` 和 `community`
- **新增芯片驱动**：需确认芯片型号和适配接口

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 miscservices 和音频框架兼容性影响
- **变更内置效果映射表**：确认对系统默认振动行为的影响
- **降级使用旧版 `hdi_service/`**：确认新功能应在 `hdi_service_2.0/` 开发
- **在 v1_x 中引入 v2_0 特性**：确认不应这样做，v2_0 是大版本合并
- **修改会话振动**：确认与音频框架的时序依赖已评估
- **新增芯片驱动**：确认芯片型号和适配接口，放在 `chipset/` 目录
- **修改 hilog_lite 依赖**：确认本仓额外依赖 `hilog_lite`（非 `hilog`）

### 项目特定陷阱

- **两套 HDI service 并存**：`hdi_service/`（旧版）和 `hdi_service_2.0/`（当前）
- **v2_0 合并特性**：v2_0 包含 v1_0-v1_3 所有方法，修改时注意不要遗漏旧方法
- **会话振动与音频框架集成**：`PlayPatternBySessionId`/`PlayPackageBySession`/`StopVibrateBySessionId` 与音频框架有时序依赖
- **hilog_lite 依赖**：本仓额外依赖 `hilog_lite`（其他 peripheral 仓通常只依赖 `hilog`）
- **community 默认 true**

## 4. 验证闭环

### 最小验证

```bash
./build.sh --product-name rk3568 --build-target drivers_peripheral_vibrator
./build.sh --product-name rk3568 --build-target hdf_test_vibrator
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 vibrator HDI + 同步构建 `drivers/interface/vibrator` + 跑 `test/unittest/` |
| HD 触觉 | 跑 `test/fuzztest/vibratorplayhapticpattern_fuzzer` + `vibratorgethapticcapacity_fuzzer` |
| 会话振动 | 跑 `test/fuzztest/vibratorplaypatternbysessionid_fuzzer` + `stopvibratebysessionid_fuzzer` |
| 芯片驱动 | 真机振动验证 |
| 内置效果 | 真机验证内置振动效果 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |

### 静态分析 / Lint

```bash
# 代码格式与静态检查
./build.sh --product-name rk3568 --build-target drivers_peripheral_vibrator --lint
# 或使用项目 clang-format 检查
clang-format --dry-run --Werror interfaces/include/ hdi_service_2.0/ hdi_impl/ hal/ chipset/ utils/
```

### Done 定义

- 构建通过（`drivers_peripheral_vibrator` + 7 个 fuzztest + 测试目标）
- 无新增编译警告
- 变更范围与任务要求一致
- 特性开关变更已同步 `vibrator.gni` + `bundle.json`
- VDI 变更已同步 `drivers/interface/vibrator` IDL
- 会话振动变更已评估与音频框架的时序依赖

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 目标服务版本（hdi_service_2.0 活跃 / hdi_service 旧版）及是否为活跃构建
4. 是否触发跨层同步修改（`drivers/interface/vibrator` IDL / `hdi_service_2.0/` 实现 / `bundle.json` / `vibrator.gni` / 下游 miscservices）
5. 是否影响特性开关默认值、内置效果映射或公共 ABI
6. 是否触及架构不变量或需确认事项
7. 涉及会话振动的变更需额外说明与音频框架的时序依赖评估
8. 涉及内置效果的变更需说明对系统默认振动行为的影响

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/vibrator` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。涉及会话振动变更的，必须人工复核与音频框架的时序依赖并说明无法在沙箱验证的限制。
