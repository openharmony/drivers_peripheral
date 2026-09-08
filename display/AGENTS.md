# AGENTS.md - OpenHarmony 显示 HDI 外设驱动（Drivers Peripheral Display）

## 1. 代码地图

本仓库实现 OpenHarmony 显示 HDI 外设驱动，提供硬件图层合成（Composer）、缓冲区管理（Buffer/Gralloc）、图形操作（GFX/VGU）及显示 HAL。核心架构边界是**上层 RenderService / 图形框架通过 `drivers/interface/display` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商显示硬件**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/display/`：HDI IDL 接口定义（composer v1_0-v1_5、buffer v1_0-v1_4、graphic/common v1_0-v2_3），由接口团队维护
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `hal/` 下的厂商特定显示驱动（如 DRM 适配）：由芯片厂商维护

### 嵌套指引

本仓目前无嵌套 AGENTS.md / CLAUDE.md / rules / skills 文件。以下子目录可按需新建嵌套 AGENTS.md：

- `composer/`：显示合成子域，可新建 `composer/AGENTS.md` 聚焦硬件图层合成、VDI 接口、版本管理
- `buffer/`：缓冲区管理子域，可新建 `buffer/AGENTS.md` 聚焦 Gralloc 分配/映射/元数据
- `hal/`：厂商 HAL 适配层，可新建 `hal/AGENTS.md` 聚焦 HAL 接口契约、DRM 适配

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `display_type.h`、`display_gralloc.h`、`display_layer.h`、`display_gfx.h`、`display_vgu.h`、`display_device.h`
- `composer/`：显示合成服务实现（硬件图层合成）
  - `composer/hdi_service/`：Composer HDI 服务（`display_composer_service.h`、VDI 接口）
  - `composer/vdi_base/`：VDI 基类
  - `composer/test/`：benchmark、fuzztest、moduletest、unittest
- `buffer/`：缓冲区管理服务（Gralloc 分配/映射）
  - `buffer/hdi_service/`：Buffer HDI 服务（`allocator_service.h`、`mapper_service.h`、`metadata_service.h`）
  - `buffer/test/`：benchmarktest、fuzztest、moduletest、unittest
- `hal/`：显示 HAL 抽象（`disp_hal.c/h`、`disp_common.h`、default 实现、default_standard 实现）
- `utils/`：工具函数
- `test/`：`unittest/` + `resources/`
- `display_config.gni`：5 个特性开关

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 图层合成 | `composer/` + `interfaces/include/display_layer.h` |
| 缓冲区分配/映射 | `buffer/` + `interfaces/include/display_gralloc.h` |
| 图形操作 | `interfaces/include/display_gfx.h` + `display_vgu.h` |
| HAL 适配（厂商特定） | `hal/` |
| 特性开关 | `display_config.gni` 的 `declare_args()` 段 |
| VDI 接口 | `composer/hdi_service/include/` + `buffer/hdi_service/include/` |
| 测试 | `test/unittest/` + `composer/test/` + `buffer/test/` |

### 架构分层

```
上层（RenderService / Graphic Framework）
  └─ proxy（由 drivers/interface/display IDL 生成）
      ↓ IPC
HDI Service
  ├─ Composer（composer/hdi_service/）— 硬件图层合成
  └─ Buffer（buffer/hdi_service/）— Gralloc 分配/映射/元数据
      ↓
HAL（hal/）— 厂商显示硬件适配
  └─ DRM / 厂商显示驱动
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改显示接口 | `interfaces/include/` → `composer/` 或 `buffer/` → `drivers/interface/display` 对应 IDL |
| 图层合成逻辑 | `composer/hdi_service/` + `drivers/interface/display/composer/` IDL |
| 缓冲区管理 | `buffer/hdi_service/` + `drivers/interface/display/buffer/` IDL |
| HAL 适配 | `hal/` + `display_config.gni` 中 VDI default 开关 |
| 特性开关变更 | `display_config.gni` + `bundle.json` |
| VDI 默认库 | `display_config.gni` 中 `drivers_peripheral_display_vdi_default` |
| HiCollie | `display_config.gni` 中 `drivers_peripheral_display_hicollie_enable` |
| 热插拔检测 | `display_config.gni` 中 `drivers_peripheral_display_bootstrap_hotplug` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API，变更需同步 composer/buffer 实现和下游 graphic framework |
| `composer/hdi_service/` | Composer HDI 服务，对应 `drivers/interface/display/composer/` IDL（v1_0-v1_5） |
| `buffer/hdi_service/` | Buffer HDI 服务，对应 `drivers/interface/display/buffer/` IDL（v1_0-v1_4） |
| `hal/` | 厂商适配层，不是框架代码，修改需了解目标硬件 |
| `display_config.gni` | 5 个特性开关，变更需同步 `bundle.json` |
| `composer/test/` | Composer 测试，含独立 fuzztest/moduletest/benchmark |
| `buffer/test/` | Buffer 测试，含独立 fuzztest/moduletest/benchmark |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| Composer | 硬件图层合成器，将多个图层合成为最终显示画面 | `composer/` |
| Gralloc | Graphics Allocator，图形内存分配器 | `buffer/` + `interfaces/include/display_gralloc.h` |
| VDI | Vendor Device Interface，厂商设备接口 | `composer/hdi_service/include/` + `buffer/hdi_service/include/` |
| VGU | Vector Graphics Unit，矢量图形单元 | `interfaces/include/display_vgu.h` |
| Hotplug | 显示设备热插拔检测 | `display_config.gni` 中 `drivers_peripheral_display_bootstrap_hotplug` |
| Community | 社区版构建，裁剪部分功能 | `display_config.gni` 中 `drivers_peripheral_display_community` |
| VDI Default | 使用默认 VDI 库实现 | `display_config.gni` 中 `drivers_peripheral_display_vdi_default` |
| DRM | Direct Rendering Manager，Linux 显示驱动框架 | `hal/` |

### 在计划阶段，必须声明

- **任务分类**（如：显示接口变更 / 图层合成变更 / 缓冲区管理变更 / HAL 适配 / 特性开关变更 / 测试修改）
- **目标子域**（composer / buffer / hal），明确涉及的 IDL 版本范围
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、Composer/Buffer 版本全部活跃、HiCollie 自动启用、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `composer/` 或 `buffer/` 实现 + `drivers/interface/display` IDL + 下游 RenderService/Graphic Framework
  - VDI 接口变更 → 同步 `drivers/interface/display` 对应版本 IDL
  - 特性开关变更 → 同步 `display_config.gni` + `bundle.json` features 列表
  - HiCollie 变更 → 评估非 community 构建下自动启用逻辑

## 3. 约束边界

### 架构不变量

- **Composer 和 Buffer 是两个独立的 HDI 服务**：有各自的版本序列和 VDI 接口
- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/display`，本仓实现服务端
- **HAL 层是厂商适配层**：不承载框架业务逻辑，只做硬件抽象
- **HiCollie 默认开启**：非 community 构建时 `drivers_peripheral_display_hicollie_enable` 自动为 true

### 禁止事项

- **不要直接修改 `drivers/interface/display` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要在 `hal/` 中写框架业务逻辑**：HAL 只做硬件抽象
- **不要在 community 构建中启用 HiCollie**：community 构建默认关闭
- **不要跳过 `display_config.gni` 中的 defines 同步**：开关变更需同步 `display_defines`
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/display` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在 `hal/` 中写框架业务逻辑②修改 IDL 文件而非通过接口评审③Composer/Buffer 所有版本活跃但只改一个版本④community 构建中启用 HiCollie⑤特性开关翻转不同步 `display_defines`

### 需确认后再修改

- **公共 API 头文件签名变更**（`interfaces/include/`）：需评估下游 RenderService、Graphic Framework 兼容性
- **Composer/Buffer VDI 接口变更**：需同步 `drivers/interface/display` 对应版本 IDL
- **特性开关默认值翻转**：特别是 `vdi_default`、`hicollie_enable`、`community`
- **新增外部依赖**：需确认许可证和 `bundle.json` 同步

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 RenderService / Graphic Framework 的兼容性影响
- **切换特性开关默认值**：确认是否影响 community 构建行为及 HiCollie 自动启用逻辑
- **新增外部依赖**：确认许可证兼容性并同步 `bundle.json`
- **修改 `drivers/interface/display` IDL**：确认已走 HDI 接口评审流程
- **在 `hal/` 中添加代码**：确认是否为纯硬件抽象，不含框架业务逻辑

### 项目特定陷阱

- **Composer 版本 v1_0-v1_5 全部活跃**：与音频/编解码不同，显示所有版本都参与构建，修改旧版本需注意向后兼容
- **Buffer 版本 v1_0-v1_4 全部活跃**：同上
- **VDI Default 开关**：`drivers_peripheral_display_vdi_default` 为 true 时使用默认 VDI 库，为 false 时需厂商提供
- **HiCollie 自动启用**：非 community 构建时即使 `display_config.gni` 中 `hicollie_enable` 默认 false，也会被自动设为 true
- **P7885 特殊配置**：`drivers_peripheral_display_feature_p7885` 为特定硬件平台配置

## 4. 验证闭环

### 最小验证

```bash
# 构建显示 HDI 驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_display

# 构建测试
./build.sh --product-name rk3568 --build-target display_test_entry
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 display HDI + 同步构建 `drivers/interface/display` + 跑 `test/unittest/` |
| Composer 变更 | 构建 composer + 跑 `composer/test/unittest/` + `composer/test/fuzztest/` |
| Buffer 变更 | 构建 buffer + 跑 `buffer/test/unittest/` + `buffer/test/fuzztest/` |
| HAL 适配 | 真机显示验证 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |
| VDI Default 切换 | `--gn-args="drivers_peripheral_display_vdi_default=true"` 重新构建 |

### 静态分析 / Lint

```bash
# 代码格式与静态检查
./build.sh --product-name rk3568 --build-target drivers_peripheral_display --lint
# 或使用项目 clang-format 检查
clang-format --dry-run --Werror interfaces/include/ composer/ buffer/ hal/ utils/
```

### Done 定义

- 构建通过（`drivers_peripheral_display` + 测试目标）
- 无新增编译警告
- 变更范围与任务要求一致
- 特性开关变更已同步 `display_config.gni` + `bundle.json`
- Composer/Buffer VDI 变更已同步 `drivers/interface/display` 对应 IDL
- HiCollie 埋点覆盖新增显示路径（非 community 构建）

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 目标子域（composer / buffer / hal）及涉及的 IDL 版本
4. 是否触发跨层同步修改（`drivers/interface/display` IDL / `composer/` 或 `buffer/` 实现 / `bundle.json` / `display_config.gni`）
5. 是否影响特性开关默认值或公共 ABI
6. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/display` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
