# AGENTS.md - OpenHarmony 灯光 HDI 外设驱动（Drivers Peripheral Light）

## 1. 代码地图

本仓库实现 OpenHarmony 灯光 HDI 外设驱动，提供 LED 灯控制（亮度、颜色、闪烁、呼吸效果），用于通知和状态指示。核心架构边界是**上层通过 `drivers/interface/light` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商灯光硬件**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/light/`：HDI IDL 接口定义，由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `hal/` 下的厂商灯光驱动：由芯片厂商维护，本仓提供 HAL 框架和 default 实现

### 嵌套指引

本仓结构较简单，目前无嵌套 AGENTS.md。以下子目录可按需新建：

- `hdi_service/`：HDI 服务实现，可新建 `hdi_service/AGENTS.md` 聚焦灯光服务 stub、效果处理
- `hdi_impl/`：HDI 实现层，可新建 `hdi_impl/AGENTS.md` 聚焦灯光操作核心逻辑
- `hal/`：厂商 HAL 适配层，可新建 `hal/AGENTS.md` 聚焦 LED 驱动适配

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `light_if.h`、`light_type.h`
- `interfaces/v1_0/`：VDI 接口头文件，含 `ilight_interface_vdi.h`、`ilight_type_vdi.h`
- `hdi_service/`：HDI 服务实现（灯光服务 stub、VDI 配置）
- `hdi_impl/`：HDI 实现层（灯光操作）
- `hal/`：硬件抽象层（厂商灯光 HAL 适配）
- `utils/`：工具函数
- `test/`：`unittest/`、`fuzztest/`、`benchmarktest/`、`performance/`
- `light.gni`：3 个特性开关

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 灯光控制逻辑 | `hdi_service/` + `hdi_impl/` + `interfaces/include/light_if.h` |
| HAL 适配 | `hal/` |
| VDI 接口 | `interfaces/v1_0/ilight_interface_vdi.h` |
| 特性开关 | `light.gni` 的 `declare_args()` 段 |
| 测试 | `test/unittest/` + `test/fuzztest/` |
| 灯光类型定义 | `interfaces/include/light_type.h` |

### 架构分层

```
上层（battery_manager 电池指示灯 / notification 通知子系统）
  └─ proxy（由 drivers/interface/light IDL 生成）
      ↓ IPC
HDI Service（hdi_service/）
  └─ HDI Impl（hdi_impl/）
      ↓
HAL（hal/）— 厂商灯光硬件适配
  └─ LED 驱动
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改灯光接口 | `interfaces/include/` → `hdi_service/` → `drivers/interface/light/v1_0/` IDL |
| 灯光效果实现 | `hdi_impl/` + `interfaces/include/light_type.h` |
| HAL 适配 | `hal/` |
| 特性开关变更 | `light.gni` + `bundle.json` |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/benchmarktest/` |
| VDI 接口变更 | `interfaces/v1_0/ilight_interface_vdi.h` → `drivers/interface/light/v1_0/` IDL |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API，变更需同步 `hdi_service/` 和下游 battery_manager |
| `interfaces/v1_0/` | VDI 接口 v1_0 版本，变更需同步 `drivers/interface/light/v1_0/` IDL |
| `hdi_service/` | HDI 服务实现，对应 `drivers/interface/light/v1_0/` IDL |
| `hdi_impl/` | HDI 实现层，灯光操作逻辑 |
| `hal/` | 厂商适配层，不是框架代码 |
| `light.gni` | 3 个特性开关，变更需同步 `bundle.json` |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| LightInfo | 灯光设备信息（亮度范围、支持模式等） | `interfaces/include/light_type.h` |
| FlashEffect | 闪烁效果（亮灭时长循环） | `interfaces/include/light_type.h` |
| BreathEffect | 呼吸效果（渐亮渐灭） | `interfaces/include/light_type.h` |
| Community | 社区版构建 | `light.gni` 中 `drivers_peripheral_light_feature_community` |
| Model | 灯光模型特性 | `light.gni` 中 `drivers_peripheral_light_feature_model` |

### 在计划阶段，必须声明

- **任务分类**（如：灯光接口变更 / 灯光效果实现 / HAL 适配 / 特性开关变更 / 测试修改）
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、community 默认 true、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `hdi_service/` 实现 + `drivers/interface/light` IDL + 下游 battery_manager
  - VDI 接口变更 → 同步 `drivers/interface/light/v1_0/` IDL
  - 特性开关变更 → 同步 `light.gni` + `bundle.json` features 列表

## 3. 约束边界

### 架构不变量

- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/light`，本仓实现服务端
- **HAL 层是厂商适配层**：不承载框架业务逻辑
- **灯光是通知指示设备**：主要消费者是 battery_manager（电池指示灯）和 notification 子系统

### 禁止事项

- **不要直接修改 `drivers/interface/light` 的 IDL 文件**
- **不要在 `hal/` 中写框架业务逻辑**
- **不要为通过测试删除日志或诊断信息**
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/light` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在 `hal/` 中写框架业务逻辑②修改 IDL 文件而非通过接口评审③community 默认 true 但误改为 false④特性开关翻转不同步 `bundle.json`

### 需确认后再修改

- **公共 API 头文件签名变更**：需评估下游 battery_manager 兼容性
- **VDI 接口变更**：需同步 `drivers/interface/light/v1_0/` IDL
- **特性开关默认值翻转**：特别是 `community` 和 `model`

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 battery_manager 兼容性影响
- **切换特性开关默认值**：确认 `community` 和 `model` 开关翻转对构建的影响
- **修改 VDI 接口**：确认已同步 `drivers/interface/light/v1_0/` IDL
- **在 `hal/` 中添加代码**：确认仅为硬件抽象，不含框架业务逻辑
- **删除日志或诊断信息**：确认不是仅为通过测试而删除

### 项目特定陷阱

- **c_utils 条件依赖**：`light.gni` 检查 `global_parts_info.commonlibrary_c_utils` 是否存在
- **community 开关默认 true**：与显示/音频不同，灯光 community 默认开启

## 4. 验证闭环

### 最小验证

```bash
./build.sh --product-name rk3568 --build-target drivers_peripheral_light
./build.sh --product-name rk3568 --build-target hdf_test_light
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 light HDI + 同步构建 `drivers/interface/light` + 跑 `test/unittest/` |
| 效果实现变更 | 跑 `hdi_impl/` 相关 unittest + fuzztest |
| HAL 适配 | 真机灯光验证 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |
| Community 开关翻转 | 验证 community 构建下功能裁剪正确 |

### 静态分析 / Lint

```bash
# 代码格式与静态检查
./build.sh --product-name rk3568 --build-target drivers_peripheral_light --lint
# 或使用项目 clang-format 检查
clang-format --dry-run --Werror interfaces/include/ hdi_service/ hdi_impl/ hal/ utils/
```

### Done 定义

- 构建通过（`drivers_peripheral_light` + 测试目标）
- 特性开关变更已同步 `light.gni` + `bundle.json`
- VDI 变更已同步 `drivers/interface/light` IDL

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 是否触发跨层同步修改（`drivers/interface/light` IDL / `hdi_service/` 实现 / `bundle.json` / `light.gni` / 下游 battery_manager）
4. 是否影响特性开关默认值或公共 ABI
5. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/light` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
