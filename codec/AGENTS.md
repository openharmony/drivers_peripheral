# AGENTS.md - OpenHarmony 编解码 HDI 外设驱动（Drivers Peripheral Codec）

## 1. 代码地图

本仓库实现 OpenHarmony 编解码 HDI 外设驱动，提供硬件编解码组件管理（Encode/Decode）、编解码图像处理（Image）及 Z-Codec 支持。核心架构边界是**上层多媒体框架通过 `drivers/interface/codec` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接 OMX 硬件编解码器**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/codec/`：HDI IDL 接口定义，由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `hal/` 下的厂商 OMX 驱动：由芯片厂商维护，本仓提供 HAL 框架和 default 实现

### 嵌套指引

本仓目前无嵌套 AGENTS.md / CLAUDE.md / rules / skills 文件。以下子目录可按需新建嵌套 AGENTS.md：

- `hal/idl_service/`：IDL 服务实现核心，可新建 `hal/idl_service/AGENTS.md` 聚焦编解码组件管理、OMX 适配
- `image/`：编解码图像子域，可新建 `image/AGENTS.md` 聚焦 HEIF/JPEG 编解码、独立 IDL 版本管理
- `zcodec/`：Z-Codec 子域，可新建 `zcodec/AGENTS.md` 聚焦 HdiZ 命名约定、下一代编解码架构
- `utils/`：共享工具，可新建 `utils/AGENTS.md` 聚焦 buffer_helper/codec_hcb_util/日志工具

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `codec_interface.h`、`codec_type.h`、`codec_common_type.h`
- `hal/`：硬件抽象层（OMX 编解码 HAL 适配），含 `hal/idl_service/` IDL 服务实现
- `hal/idl_service/include/`：内部服务头文件（`codec_omx_core.h`、`component_mgr.h`、`component_node.h` 等）
- `image/`：编解码图像处理实现（hdi_service、heif、jpeg、vdi、config）
- `zcodec/`：Z-Codec 实现（下一代编解码，VDI 支持）
- `utils/`：共享工具（`buffer_helper`、`codec_hcb_util`、`codec_log_wrapper`）
- `utils/include/`：工具头文件
- `test/`：`unittest/`、`fuzztest/`、`benchmarktest/`、`demo/`

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 编解码组件管理 | `hal/idl_service/` + `interfaces/include/codec_interface.h` |
| 编解码图像处理 | `image/` + `drivers/interface/codec/image/` IDL |
| Z-Codec | `zcodec/` + `drivers/interface/codec/zcodec/` IDL |
| HAL 适配（OMX） | `hal/` |
| 特性开关 | `codec.gni` 的 `declare_args()` 段 |
| 编解码类型定义 | `interfaces/include/codec_type.h` + `codec_common_type.h` |
| 测试 | `test/unittest/` + `test/fuzztest/` + `test/demo/` |

### 架构分层

```
上层（multimedia framework）
  └─ proxy（由 drivers/interface/codec IDL 生成）
      ↓ IPC
HDI Service（hal/idl_service/）
  ├─ CodecComponentManager（组件管理）
  ├─ CodecComponent（编解码组件）
  ├─ CodecCallback（回调通知）
  └─ Image（编解码图像）/ ZCodec
      ↓
HAL（hal/，OMX 适配层）
  └─ 硬件编解码器
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改编解码接口 | `interfaces/include/` → `hal/idl_service/` → `drivers/interface/codec` 对应 IDL |
| 编解码图像 | `image/` + `drivers/interface/codec/image/` IDL |
| Z-Codec | `zcodec/` + `drivers/interface/codec/zcodec/` IDL |
| HAL 适配（OMX） | `hal/` + `codec.gni` 中 OMX 相关开关 |
| 特性开关变更 | `codec.gni` `declare_args()` + `bundle.json` |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/benchmarktest/` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API，变更需同步 `hal/idl_service/` 和下游 multimedia |
| `hal/idl_service/` | IDL 服务实现，对应 `drivers/interface/codec` 的 IDL 定义 |
| `hal/` | OMX 硬件适配层，不是框架代码 |
| `image/` | 编解码图像，有独立 IDL 版本（`drivers/interface/codec/image/`） |
| `zcodec/` | Z-Codec，有独立 IDL（`drivers/interface/codec/zcodec/`），命名前缀 `HdiZ` |
| `codec.gni` | 6 个特性开关，变更需同步 `bundle.json` |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| OMX | OpenMAX，开放多媒体加速层标准 | `hal/` |
| Component | 编解码组件实例 | `interfaces/include/codec_interface.h` |
| HEIF | High Efficiency Image Format，高效图像格式 | `codec.gni` 中 `drivers_peripheral_codec_feature_support_heif_test` |
| Z-Codec | Z 轴编解码，下一代编解码架构 | `zcodec/` |
| DMA Buffer | 直接内存访问缓冲区 | `codec.gni` 中 `drivers_peripheral_codec_feature_support_dma_buffer` |
| OMX Role | OMX 角色标识，用于匹配编解码器 | `codec.gni` 中 `drivers_peripheral_codec_feature_set_omx_role` |
| HDI v1 | HDI 版本 1 向后兼容 | `codec.gni` 中 `drivers_peripheral_codec_feature_support_hdi_v1` |

### 在计划阶段，必须声明

- **任务分类**（如：编解码接口变更 / 图像编解码变更 / Z-Codec 变更 / HAL 适配 / 特性开关变更 / 测试修改）
- **目标子域与版本**（主 codec / image / zcodec），明确涉及的 IDL 版本
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、OMX Role 匹配、DMA Buffer 路径、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `hal/idl_service/` 实现 + `drivers/interface/codec` IDL + 下游 multimedia
  - Image 变更 → 同步 `drivers/interface/codec/image/` IDL
  - Z-Codec 变更 → 同步 `drivers/interface/codec/zcodec/` IDL
  - 特性开关变更 → 同步 `codec.gni` + `bundle.json` features 列表

## 3. 约束边界

### 架构不变量

- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/codec`，本仓实现服务端
- **HAL 层是 OMX 适配层**：不承载框架业务逻辑，只做硬件编解码抽象
- **Image 和 Z-Codec 有独立 IDL 版本**：与主 codec IDL 分开版本管理
- **HDI v1 兼容**：`drivers_peripheral_codec_feature_support_hdi_v1` 控制是否支持旧版接口

### 禁止事项

- **不要直接修改 `drivers/interface/codec` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要在 `hal/` 中写框架业务逻辑**：HAL 只做 OMX 硬件抽象
- **不要跳过 `utils/` 中的 buffer_helper**：编解码缓冲区管理需走统一工具
- **不要混淆 Z-Codec 命名前缀**：Z-Codec IDL 使用 `HdiZ` 前缀，主 codec 使用 `I` 前缀
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/codec` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①混淆 Z-Codec `HdiZ` 前缀与主 codec `I` 前缀②在 `hal/` 中写框架业务逻辑③Image 版本与主 codec 版本号误判对应关系④特性开关翻转不同步 `bundle.json`

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 multimedia 兼容性影响
- **切换特性开关默认值**：确认 codec.gni 中 support_hdi_v1/support_dma_buffer/set_omx_role 开关翻转的影响
- **修改 Image 或 Z-Codec 版本**：确认独立 IDL 版本兼容性
- **修改 Z-Codec 命名**：确认 HdiZ 前缀一致性

### 需确认后再修改

- **公共 API 头文件签名变更**（`interfaces/include/`）：需评估下游 multimedia 兼容性
- **特性开关默认值翻转**：特别是 `support_hdi_v1`、`support_dma_buffer`、`set_omx_role`
- **新增外部依赖**：需确认许可证和 `bundle.json` 同步

### 项目特定陷阱

- **OMX Role 设置**：`drivers_peripheral_codec_feature_set_omx_role` 为 true 时需确保 OMX 角色匹配正确
- **DMA Buffer 支持**：`drivers_peripheral_codec_feature_support_dma_buffer` 影响 buffer 分配路径
- **高频工作模式**：`drivers_peripheral_codec_feature_support_high_work_frequency` 影响编解码性能和功耗
- **Image vs 主 Codec 版本独立**：`image/v2_1` 是当前构建版本，与主 codec `v4_0` 版本号不对应

## 4. 验证闭环

### 最小验证

```bash
# 构建编解码 HDI 驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_codec

# 构建测试
./build.sh --product-name rk3568 --build-target hdf_test_media_codec

# 静态分析
cppcheck --enable=all --error-exitcode=1 hal/idl_service/ image/ zcodec/ utils/ 2>/dev/null || true
clang-format --dry-run --Werror interfaces/include/ hal/ image/ zcodec/ utils/ 2>/dev/null || true
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 codec HDI + 同步构建 `drivers/interface/codec` + 跑 `test/unittest/` + 运行 API 兼容性检查（`idl-check` 对比新旧 IDL） + 静态分析 |
| 编解码图像 | 构建 image 子模块 + 验证 HEIF/JPEG 编解码 + 静态分析 |
| Z-Codec | 构建 zcodec 子模块 + 验证 Z-Codec 流程 + 静态分析 |
| HAL 适配 | 真机编解码验证 + 静态分析 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 + 静态分析 |

### Done 定义

- 构建通过（`drivers_peripheral_codec` + 测试目标）
- 无新增编译警告
- 无 lint/static analysis 违规（cppcheck/clang-format）
- 变更范围与任务要求一致
- 特性开关变更已同步 `codec.gni` + `bundle.json`
- Image/Z-Codec 变更已同步 `drivers/interface/codec` 对应 IDL
- API 兼容性检查通过（涉及 IDL 变更时）

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果（含 lint/static analysis 结果）
3. 目标子域与版本（主 codec / image / zcodec）及是否为活跃构建
4. 是否触发跨层同步修改（`drivers/interface/codec` IDL / `hal/idl_service/` 实现 / `bundle.json` / `codec.gni`）
5. 是否影响特性开关默认值或公共 ABI
6. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/codec` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
