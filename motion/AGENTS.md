# AGENTS.md - OpenHarmony 动作 HDI 外设驱动（Drivers Peripheral Motion）

## 1. 代码地图

本仓库实现 OpenHarmony 动作 HDI 外设驱动，提供动作手势检测（拾起、翻转、摇晃、倾斜、旋转）用于设备交互。核心架构边界是**上层通过 `drivers/interface/motion` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现**。本仓无传统 HAL 层，使用 hdi_service 直接对接传感器数据。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/motion/`：HDI IDL 接口定义（v1_0 和 v1_1），由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- miscservices 中消费 Motion 接口的代码：由上层服务团队维护

### 嵌套指引

本仓结构较简单（无 HAL 层），目前无嵌套 AGENTS.md。以下子目录可按需新建：

- `hdi_service/`：HDI 服务实现，可新建 `hdi_service/AGENTS.md` 聚焦动作检测服务 stub、基于传感器数据的动作识别
- `utils/`：工具函数，可新建 `utils/AGENTS.md` 聚焦日志、通用工具

### 关键区域

- `interfaces/v1_0/`：VDI 接口头文件，含 `imotion_interface_vdi.h`、`imotion_callback_vdi.h`（无 `interfaces/include/` 目录，直接使用 VDI）
- `hdi_service/`：HDI 服务实现（动作服务 stub、VDI 配置）
- `utils/`：工具函数
- `test/`：`unittest/`、`fuzztest/`、`benchmark/`
- `motion.gni`：2 个特性开关

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 动作检测逻辑 | `hdi_service/` + `interfaces/v1_0/imotion_interface_vdi.h` |
| 动作回调 | `interfaces/v1_0/imotion_callback_vdi.h` |
| 特性开关 | `motion.gni` 的 `declare_args()` 段 |
| 测试 | `test/unittest/` + `test/fuzztest/` |

### 架构分层

```
上层（miscservices 动作检测服务）
  └─ proxy（由 drivers/interface/motion IDL 生成）
      ↓ IPC
HDI Service（hdi_service/）
  └─ 动作检测（基于传感器数据）
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改动作接口 | `interfaces/v1_0/` → `hdi_service/` → `drivers/interface/motion` IDL |
| 动作检测实现 | `hdi_service/` |
| 特性开关变更 | `motion.gni` + `bundle.json` |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/benchmark/` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/v1_0/` | VDI 接口，版本化，变更需同步 `drivers/interface/motion` |
| `hdi_service/` | HDI 服务实现，对应 `drivers/interface/motion/v1_0/` 和 `v1_1/` IDL |
| `motion.gni` | 2 个特性开关，变更需同步 `bundle.json` |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| Motion | 动作手势检测 | `interfaces/v1_0/imotion_interface_vdi.h` |
| Pickup | 拾起动作 | `drivers/interface/motion/v1_0/MotionTypes.idl` |
| Flip | 翻转动作 | `drivers/interface/motion/v1_0/MotionTypes.idl` |
| Community | 社区版构建 | `motion.gni` 中 `drivers_peripheral_motion_feature_community` |

### 在计划阶段，必须声明

- **任务分类**（如：动作接口变更 / 动作检测实现 / 特性开关变更 / 测试修改）
- **目标接口版本**（v1_0 / v1_1），明确两个版本同时活跃
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、无 HAL 层、v1_0 和 v1_1 双版本兼容、跨仓同步需求）
- **是否需要同步修改其他层**：
  - VDI 接口变更 → 同步 `drivers/interface/motion/v1_0/` 和 `v1_1/` IDL
  - 动作检测变更 → 评估与传感器数据的时序依赖
  - 特性开关变更 → 同步 `motion.gni` + `bundle.json` features 列表

## 3. 约束边界

### 架构不变量

- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/motion`，本仓实现服务端
- **无传统 HAL 层**：动作检测基于传感器数据，不直接对接硬件
- **v1_0 和 v1_1 都活跃**：两个版本同时构建，需保持向后兼容

### 禁止事项

- **不要直接修改 `drivers/interface/motion` 的 IDL 文件**
- **不要引入 HAL 层**：本仓架构不使用 HAL
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/motion` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①引入 HAL 层（本仓架构不使用 HAL）②修改 IDL 文件而非通过接口评审③v1_0/v1_1 双版本只改一个④特性开关翻转不同步 `bundle.json`

### 需确认后再修改

- **VDI 接口变更**：需同步 `drivers/interface/motion/v1_0/` 和 `v1_1/` IDL
- **特性开关默认值翻转**：特别是 `community` 和 `model`

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改 VDI 接口**：确认已同步 `drivers/interface/motion/v1_0/` 和 `v1_1/` IDL，双版本兼容
- **引入 HAL 层**：确认本仓架构不使用 HAL，不要引入
- **切换特性开关默认值**：确认 `community` 和 `model` 开关翻转的影响
- **修改 v1_0 或 v1_1 单版本**：确认双版本向后兼容性

### 项目特定陷阱

- **c_utils 条件依赖**：`motion.gni` 检查 `global_parts_info.commonlibrary_c_utils`
- **无 HAL 层**：与其他 peripheral 仓不同，不要在此仓引入 HAL
- **community 默认 true**

## 4. 验证闭环

### 最小验证

```bash
./build.sh --product-name rk3568 --build-target drivers_peripheral_motion
./build.sh --product-name rk3568 --build-target hdf_test_motion
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 motion HDI + 同步构建 `drivers/interface/motion` + 跑 `test/unittest/` |
| 动作检测实现变更 | 跑 `hdi_service/` 相关 unittest + fuzztest |
| v1_0/v1_1 双版本兼容 | 分别构建 v1_0 和 v1_1 目标 + 跑双版本 unittest |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |

### 静态分析 / Lint

```bash
# 代码格式与静态检查
./build.sh --product-name rk3568 --build-target drivers_peripheral_motion --lint
# 或使用项目 clang-format 检查
clang-format --dry-run --Werror interfaces/v1_0/ hdi_service/ utils/
```

### Done 定义

- 构建通过（`drivers_peripheral_motion` + 测试目标）
- 特性开关变更已同步 `motion.gni` + `bundle.json`
- VDI 变更已同步 `drivers/interface/motion` IDL

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 目标版本（v1_0 / v1_1）及双版本兼容性评估
4. 是否触发跨层同步修改（`drivers/interface/motion` IDL / `hdi_service/` 实现 / `bundle.json` / `motion.gni`）
5. 是否影响特性开关默认值或公共 ABI
6. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/motion` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
