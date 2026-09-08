# AGENTS.md - OpenHarmony 驱动外设层（Drivers Peripheral）

## 0. Where to look

| 遇到问题 | 读取路径 |
|----------|----------|
| 不确定哪个子域负责 | 顶部「子域索引」表 |
| 需要知道接口定义 | `drivers/interface/*/AGENTS.md` |
| 需要知道HAL适配 | 对应子域 `hal/` 目录 |
| 需要构建命令 | 顶部「各子域构建命令」表 |
| 需要术语→文件映射 | 顶部「术语路由」表 |
| 需要特性开关 | 对应子域 `*.gni` + `bundle.json` |

## 1. 代码地图

本仓库是 OpenHarmony 驱动外设层，包含多个子域的外设驱动实现。每个子域实现特定的硬件功能，通过 `drivers/interface/*` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商硬件。

### 任务到路径映射

| 任务类型 | 入口路径 | 说明 |
|----------|----------|------|
| 音频接口变更 | `drivers/peripheral/audio/` | 音频渲染/录音/效果 |
| 编解码接口变更 | `drivers/peripheral/codec/` | 编解码/图像/Z-Codec |
| 显示合成/缓冲变更 | `drivers/peripheral/display/` | 图层合成/缓冲区/图形 |
| 灯光控制变更 | `drivers/peripheral/light/` | LED灯光控制 |
| 动作检测变更 | `drivers/peripheral/motion/` | 动作手势检测 |
| 传感器类型/接口变更 | `drivers/peripheral/sensor/` | 传感器数据采集 |
| 振动/HD触觉变更 | `drivers/peripheral/vibrator/` | 振动/HD触觉/会话 |
| 驱动宿主进程变更 | `drivers/peripheral/devhost/` | 驱动宿主进程(hdf_devhost) |

### 子域索引

| 子域 | 功能 | AGENTS.md | 特性开关 | 活跃版本 |
|------|------|-----------|----------|----------|
| [audio](audio/AGENTS.md) | 音频渲染/录音/效果 | [查看](audio/AGENTS.md) | `audio.gni` (19个开关) | v1_0 |
| [codec](codec/AGENTS.md) | 编解码/图像/Z-Codec | [查看](codec/AGENTS.md) | `codec.gni` (6个开关) | v4_0 |
| [devhost](devhost/AGENTS.md) | 驱动宿主进程(hdf_devhost) | [查看](devhost/AGENTS.md) | 无 | - |
| [display](display/AGENTS.md) | 图层合成/缓冲区/图形 | [查看](display/AGENTS.md) | `display_config.gni` (5个开关) | v1_0-v1_5 |
| [light](light/AGENTS.md) | LED灯光控制 | [查看](light/AGENTS.md) | `light.gni` (3个开关) | v1_0 |
| [motion](motion/AGENTS.md) | 动作手势检测 | [查看](motion/AGENTS.md) | `motion.gni` (2个开关) | v1_0/v1_1 |
| [sensor](sensor/AGENTS.md) | 传感器数据采集 | [查看](sensor/AGENTS.md) | `sensor.gni` (4个开关) | v3_0/v3_1 |
| [vibrator](vibrator/AGENTS.md) | 振动/HD触觉/会话 | [查看](vibrator/AGENTS.md) | `vibrator.gni` (4个开关) | v2_0 |

### 架构边界

- **上层**：通过 `drivers/interface/*` 的 IDL 生成的 proxy 调用本仓 HDI service
- **本仓**：实现 HDI service stub，对接 HAL 层
- **HAL 层**：厂商硬件适配层，不承载框架业务逻辑
- **接口定义**：由 `drivers/interface/*` 仓维护，本仓是实现方

### 非本项目维护的目录

- `drivers/interface/*/`：HDI IDL 接口定义，由接口团队维护
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物）
- `hal/` 下的厂商特定驱动：由芯片厂商维护

## 2. 知识路由

### 计划阶段声明

在计划阶段，必须声明以下内容：
1. 目标子域及版本
2. 是否需要修改 `drivers/interface/*` 的 IDL
3. 是否需要同步 `bundle.json` 特性开关
4. 是否需要跨层同步修改

### 按子域路由

| 任务类型 | 子域 | 读取 |
|----------|------|------|
| 音频接口变更 | audio | [audio/AGENTS.md](audio/AGENTS.md) |
| 编解码接口变更 | codec | [codec/AGENTS.md](codec/AGENTS.md) |
| 显示合成/缓冲变更 | display | [display/AGENTS.md](display/AGENTS.md) |
| 灯光控制变更 | light | [light/AGENTS.md](light/AGENTS.md) |
| 动作检测变更 | motion | [motion/AGENTS.md](motion/AGENTS.md) |
| 传感器类型/接口变更 | sensor | [sensor/AGENTS.md](sensor/AGENTS.md) |
| 振动/HD触觉变更 | vibrator | [vibrator/AGENTS.md](vibrator/AGENTS.md) |
| 驱动宿主进程变更 | devhost | [devhost/AGENTS.md](devhost/AGENTS.md) |
| 特性开关变更 | 对应子域 | 对应子域 AGENTS.md |
| 测试修改 | 对应子域 | 对应子域 AGENTS.md |

### 按任务类型路由

| 任务类型 | 操作 |
|----------|------|
| 新增/修改接口 | 先读对应子域 AGENTS.md → `drivers/interface/*` IDL → 实现 |
| 特性开关变更 | 读对应子域 AGENTS.md → `*.gni` + `bundle.json` |
| HAL 适配 | 读对应子域 AGENTS.md 的 HAL 部分 |
| 芯片驱动适配 | 读 sensor 的 `chipset/` 或 vibrator 的 `chipset/` |
| 构建配置变更 | 读对应子域 AGENTS.md 的构建部分 |

### 术语路由

| 术语 | 含义 | 读取路径 |
|------|------|----------|
| HDI service | 硬件驱动接口服务层 | `drivers/peripheral/*/hdi_service_*/` |
| proxy | 上层调用代理 | `drivers/interface/*/` 生成代码 |
| stub | 下层实现桩 | `drivers/peripheral/*/hdi_service_*/` |
| bundle.json | 组件配置文件 | `drivers/peripheral/*/bundle.json` |
| *.gni | 构建配置文件 | `drivers/peripheral/*/*.gni` |
| hdi-gen | IDL代码生成工具 | 构建系统自动调用 |
| HAL | 硬件抽象层 | `drivers/peripheral/*/hal/` |
| chipset | 芯片适配代码 | `drivers/peripheral/sensor/chipset/` 或 `drivers/peripheral/vibrator/chipset/` |
| inner_kits | 内部SDK组件列表 | `bundle.json` 内字段 |
| feature开关 | 特性编译开关 | `*.gni` + `bundle.json` features |
| IDL | 接口定义语言 | `drivers/interface/*/*.idl` |
| 构建产物 | hdi-gen生成的代码 | 由构建系统自动生成，不手动修改 |

## 3. 约束边界

### 计划阶段必须声明

开始任何任务前，必须声明：
- 目标子域和版本
- 是否修改 IDL（`drivers/interface/*`）
- 是否修改特性开关（`bundle.json`/`*.gni`）
- 是否需要跨层同步

### 通用约束

- **不要直接修改 `drivers/interface/*` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要在 `hal/` 中写框架业务逻辑**：HAL 只做硬件抽象
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `.idl` 源文件后由构建系统重生成
- **特性开关变更必须同步 `bundle.json`**：所有子域均适用
- **不要在 community 构建中引入 rich_device 专属功能**

### Ask-before 规则

在执行以下操作前，必须先确认：

| 操作 | 确认内容 | 确认对象 |
|------|----------|----------|
| 修改 `bundle.json` | inner_kits 列表是否同步更新 | 项目负责人 |
| 修改 IDL 文件 | 是否已走 HDI 接口评审流程 | 接口团队 |
| 新增版本目录 | 是否已确认版本号与 `bundle.json` 一致 | 项目负责人 |
| 修改特性开关默认值 | 是否影响其他子域构建 | 构建团队 |
| 修改 `hdi_service_*` 回调接口 | 是否影响 `proxy_deps`/`stub_deps` | 项目负责人 |
| 在 community 构建中启用功能 | 是否已检查 `rich_device` 专属功能标记 | 构建团队 |
| 修改 `BUILD.gn` 依赖 | 是否引入新的生产依赖 | 依赖评审团队 |

### Agent 失败模式

| 失败模式 | 描述 | 预防 |
|----------|------|------|
| 手改生成代码 | 直接修改 `hdi-gen` 生成的 proxy/stub 代码 | 始终修改 `.idl` 源文件后由构建系统重生成 |
| 版本混淆 | 在 v1_0 中引入 v2_0 特有功能，或在 legacy 版本中新增能力 | 确认目标版本活跃性，参考「按接口版本路由」 |
| ABI 破坏 | 修改 IDL 中字段顺序或方法签名 | 跨版本交互必须通过版本化库显式选择 |
| 跨层同步遗漏 | 修改了特性开关但未同步 `bundle.json` | 修改特性开关后必须验证 `bundle.json` |
| 依赖遗漏 | 新增依赖但未在 `bundle.json` 中声明 | 所有生产依赖必须经过 `bundle.json` 评审 |
| 构建类型混淆 | 在 community 构建中引入 rich_device 专属功能 | 检查 `OAT.xml` 和 `BUILD.gn` 的构建类型 |
| 内核工具误用 | 在非对应的子域中使用内核工具（如 sensor 的 hdi_service 调用 audio 的） | 确认目标子域和版本一致性 |

### 子域特定约束

- **sensor**: `hdi_service_3.0/` 是当前活跃服务，`chipset/` 中不要交叉修改不同传感器类型
- **vibrator**: `hdi_service_2.0/` 是当前活跃服务，`hilog_lite` 是唯一依赖 hilog_lite 的接口仓
- **display**: 所有版本（composer v1_0-v1_5, buffer v1_0-v1_4）全部活跃构建
- **motion**: 无传统 HAL 层，v1_0 和 v1_1 双版本同时活跃
- **devhost**: 仅包含进程入口（main 函数），不要在此仓添加业务逻辑

## 4. 验证闭环

### 各子域构建命令

| 子域 | 构建命令 | 测试命令 |
|------|----------|----------|
| audio | `./build.sh --product-name rk3568 --build-target drivers_peripheral_audio` | `./build.sh --product-name rk3568 --build-target hdf_test_audio` |
| codec | `./build.sh --product-name rk3568 --build-target drivers_peripheral_codec` | `./build.sh --product-name rk3568 --build-target hdf_test_media_codec` |
| devhost | `./build.sh --product-name rk3568 --build-target drivers_devhost` | - |
| display | `./build.sh --product-name rk3568 --build-target drivers_peripheral_display` | `./build.sh --product-name rk3568 --build-target display_test_entry` |
| light | `./build.sh --product-name rk3568 --build-target drivers_peripheral_light` | `./build.sh --product-name rk3568 --build-target hdf_test_light` |
| motion | `./build.sh --product-name rk3568 --build-target drivers_peripheral_motion` | `./build.sh --product-name rk3568 --build-target hdf_test_motion` |
| sensor | `./build.sh --product-name rk3568 --build-target drivers_peripheral_sensor` | `./build.sh --product-name rk3568 --build-target hdf_test_sensor` |
| vibrator | `./build.sh --product-name rk3568 --build-target drivers_peripheral_vibrator` | `./build.sh --product-name rk3568 --build-target hdf_test_vibrator` |

### 任务特定验证表

| 任务类型 | 验证命令 | 验证目标 |
|----------|----------|----------|
| 新增/修改 IDL | `./build.sh --product-name rk3568 --build-target drivers_interface_[module] --lint` | IDL 生成一致性 |
| 特性开关变更 | `./build.sh --product-name rk3568 --build-target <subdomain> --lint` | bundle.json 同步 |
| HAL 适配 | `./build.sh --product-name rk3568 --build-target <subdomain>` | 构建通过 |
| 芯片驱动适配 | `./build.sh --product-name rk3568 --build-target <subdomain>` | 芯片兼容 |
| 构建配置变更 | `gn gen --check && hdi-gen --check` | 配置正确性 |
| 跨层同步 | 检查 `drivers/interface/*` 和 `drivers/peripheral/*` 同步 | IDL 与实现匹配 |

### 通用验证步骤

```bash
# 构建目标子域
./build.sh --product-name rk3568 --build-target <target>

# 静态分析（Lint）
./build.sh --product-name rk3568 --build-target <target> --lint
clang-format --dry-run --Werror <子域目录>
cppcheck --enable=all --error-exitcode=1 <子域目录>

# IDL 一致性检查
hdi-gen --check

# 运行测试
./build.sh --product-name rk3568 --build-target <test_target>
```

### Done 定义

任务完成的判定标准：
1. 构建命令执行成功（`./build.sh --product-name rk3568 --build-target <target>` 返回 0）
2. 静态分析通过（`--lint` 返回 0，`clang-format --dry-run --Werror` 无差异）
3. 测试命令执行成功（如有）
4. `bundle.json` 中的特性开关已同步更新
5. 跨层同步已验证（IDL 与实现匹配）
6. 最终报告已输出（包含文件清单、验证结果、确认事项）

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 是否触发跨层同步修改（`drivers/interface/*` IDL / 实现 / `bundle.json` / `*.gni`）
4. 是否影响特性开关默认值或公共 ABI
5. 是否触及架构不变量或需确认事项
6. 所有验证命令的执行结果（构建/测试/lint/静态分析）

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样。涉及 `drivers/interface/*` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
