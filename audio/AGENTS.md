# AGENTS.md - OpenHarmony 音频 HDI 外设驱动（Drivers Peripheral Audio）

## 1. 代码地图

本仓库实现 OpenHarmony 音频 HDI 外设驱动，提供音频渲染（Render）、录音（Capture）、适配器管理（Adapter）、音效处理（Effect）及音频 HAL 抽象。核心架构边界是**上层通过 `drivers/interface/audio` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商硬件**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/audio/`：HDI IDL 接口定义，由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `hal/` 下的厂商特定驱动：由芯片厂商维护，本仓提供 HAL 框架和 default 实现

### 嵌套指引

本仓目前无嵌套 AGENTS.md / CLAUDE.md / rules / skills 文件。以下子目录可按需新建嵌套 AGENTS.md：

- `hdi_service/`：HDI 服务实现核心，可新建 `hdi_service/AGENTS.md` 聚焦服务 stub 实现、适配器管理、渲染/录音数据通路
- `hal/`：厂商 HAL 适配层，可新建 `hal/AGENTS.md` 聚焦 HAL 接口契约、厂商适配规范
- `audio_dfx/`：DFX 支持，可新建 `audio_dfx/AGENTS.md` 聚焦 HiSysEvent/HiCollie/HiTrace 集成
- `effect/`：音效模型实现，可新建 `effect/AGENTS.md` 聚焦音效链路、特性开关控制

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `audio_manager.h`、`audio_render.h`、`audio_capture.h`、`audio_types.h`、`audio_attribute.h`、`audio_scene.h`、`audio_events.h`、`audio_stream.h`
- `interfaces/sound/v1_0/`：VDI 接口头文件，含 `iaudio_manager_vdi.h`、`iaudio_adapter_vdi.h`、`iaudio_render_vdi.h`、`iaudio_capture_vdi.h`、`iaudio_callback_vdi.h`、`audio_types_vdi.h`
- `interfaces/effect/v1_0/`：音效 VDI 头文件，含 `ieffect_control_vdi.h`、`effect_types_vdi.h`、`effect_factory.h`
- `hdi_service/`：HDI 服务实现（音频管理、适配器、渲染、录音服务 stub）
- `hal/`：硬件抽象层（厂商音频 HAL 适配）
- `effect/`：音效模型实现
- `supportlibs/`：支持库
- `config/`：音频配置文件
- `audio_dfx/`：DFX 支持（HiSysEvent、HiCollie、HiTrace）
- `test/`：`unittest/`、`systemtest/`、`fuzztest/`、`benchmarktest/`、`concurrencytest/`、`sample/`

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 音频渲染/录音逻辑 | `hdi_service/` + `interfaces/include/audio_render.h` / `audio_capture.h` |
| 音效处理 | `effect/` + `interfaces/effect/v1_0/` |
| HAL 适配（厂商特定） | `hal/` |
| 特性开关 | `audio.gni` 的 `declare_args()` 段 |
| VDI 接口变更 | `interfaces/sound/v1_0/` 或 `interfaces/effect/v1_0/` |
| DFX（日志/事件） | `audio_dfx/` + `audio.gni` 中 hicollie/hitrace/hisysevent 开关 |
| ALSA 库支持 | `audio.gni` 中 `drivers_peripheral_audio_feature_alsa_lib` |
| 测试 | `test/unittest/` + `test/fuzztest/` + `test/systemtest/` |

### 架构分层

```
上层（audio_service / multimedia）
  └─ proxy（由 drivers/interface/audio IDL 生成）
      ↓ IPC
HDI Service（hdi_service/）
  ├─ AudioManager / AudioAdapter / AudioRender / AudioCapture
  ├─ Effect（effect/，特性开关控制）
  └─ DFX（audio_dfx/）
      ↓
HAL（hal/，厂商适配层）
  └─ 硬件音频驱动
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改音频接口 | `interfaces/include/*.h` + `interfaces/sound/v1_0/*.h` → `hdi_service/` 实现 → `drivers/interface/audio` 对应 IDL |
| 音效功能 | `effect/` + `interfaces/effect/v1_0/` + `audio.gni` 中 `drivers_peripheral_audio_feature_effect` |
| HAL 适配 | `hal/` + `audio.gni` 中 ALSA 相关开关 |
| 特性开关变更 | `audio.gni` `declare_args()` + `bundle.json` |
| DFX 变更 | `audio_dfx/` + `audio.gni` 中 hicollie/hitrace/hisysevent 开关 |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/benchmarktest/` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API 头文件，变更需同步 `hdi_service/` 实现和下游消费者 |
| `interfaces/sound/v1_0/` | VDI 接口定义，版本化，不要破坏现有版本 |
| `interfaces/effect/v1_0/` | 音效 VDI 接口，受 `drivers_peripheral_audio_feature_effect` 开关控制 |
| `hal/` | 厂商适配层，不是框架代码，修改需了解目标硬件 |
| `audio.gni` | 19 个特性开关，变更需同步 `bundle.json` 的 `features` 列表 |
| `hdi_service/` | HDI 服务实现，对应 `drivers/interface/audio` 的 IDL 定义 |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| VDI | Vendor Device Interface，厂商设备接口，HDI 的下层抽象 | `interfaces/sound/v1_0/` |
| Render | 音频渲染（播放）通道 | `interfaces/include/audio_render.h` |
| Capture | 音频录音通道 | `interfaces/include/audio_capture.h` |
| Adapter | 音频适配器，管理一组 Render/Capture | `interfaces/include/audio_attribute.h` |
| Effect | 音效处理，特性开关默认关闭 | `effect/` + `audio.gni` |
| ALSA | Advanced Linux Sound Architecture，Linux 音频驱动框架 | `audio.gni` 中 `drivers_peripheral_audio_feature_alsa_lib` |
| Community | 社区版构建，裁剪部分功能 | `audio.gni` 中 `drivers_peripheral_audio_feature_community` |
| Offload | 音频卸载，将音频处理卸载到硬件 | `audio.gni` 中 `drivers_peripheral_audio_feature_offload` |

### 在计划阶段，必须声明

- **任务分类**（如：音频接口变更 / 音效功能变更 / HAL 适配 / 特性开关变更 / DFX 变更 / 测试修改）
- **目标接口版本**（interfaces/include/ 公共 API / interfaces/sound/v1_0/ VDI / interfaces/effect/v1_0/ 音效 VDI）
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、特性开关联动、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `hdi_service/` 实现 + `drivers/interface/audio` IDL + 下游 audio_service/multimedia
  - VDI 接口变更 → 同步 `drivers/interface/audio` 对应 IDL
  - 特性开关变更 → 同步 `audio.gni` + `bundle.json` features 列表
  - DFX 变更 → 评估 hicollie/hitrace/hisysevent 埋点覆盖

## 3. 约束边界

### 架构不变量

- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/audio`，本仓实现服务端，不要反向修改 IDL
- **HAL 层是厂商适配层**：不承载框架业务逻辑，只做硬件抽象
- **VDI 接口版本化**：`interfaces/sound/v1_0/` 和 `interfaces/effect/v1_0/` 是版本化接口，新增字段追加不破坏
- **DFX 必须覆盖关键路径**：hicollie/hitrace/hisysevent 开关默认开启（非 community）

### 禁止事项

- **不要直接修改 `drivers/interface/audio` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要在 `hal/` 中写框架业务逻辑**：HAL 只做硬件抽象
- **不要跳过 DFX 检查**：新增音频路径需同步添加 hicollie/hitrace/hisysevent 埋点
- **不要为通过测试删除日志或诊断信息**
- **不要在 community 构建中引入 rich_device 专属功能**
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/audio` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在 `hal/` 中写框架业务逻辑②修改 IDL 文件而非通过接口评审③特性开关翻转不同步 `bundle.json`④community 构建中引入 rich_device 功能

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 audio_service/multimedia 兼容性影响
- **切换特性开关默认值**：确认 audio.gni 中 alsa_lib/offload/community 开关翻转的影响
- **修改 VDI 接口**：确认已同步 `drivers/interface/audio` 对应版本 IDL
- **修改特性开关**：确认 audio.gni + bundle.json features 列表同步

### 需确认后再修改

- **公共 API 头文件签名变更**（`interfaces/include/`）：需评估下游 audio_service、multimedia 兼容性
- **VDI 接口变更**（`interfaces/sound/v1_0/`、`interfaces/effect/v1_0/`）：需同步 `drivers/interface/audio` IDL
- **特性开关默认值翻转**：特别是 effect、alsa_lib、offload、community 开关
- **新增外部依赖**：需确认许可证和 `bundle.json` 同步

### 项目特定陷阱

- **特性开关双写**：`audio.gni` 中开关既要改 `declare_args()` 默认值，也要在对应 `if` 块更新 `defines`
- **community vs rich_device**：两个开关互斥，同时为 true 时行为未定义
- **proxy_stub 开关**：`drivers_peripheral_audio_feature_hdf_proxy_stub` 控制 proxy/stub 编译，关闭后无法 IPC
- **ALSA 路径**：`drivers_peripheral_audio_vendor_alsa_path` 为空时使用默认路径

## 4. 验证闭环

### 最小验证

```bash
# 构建音频 HDI 驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_audio

# 构建测试
./build.sh --product-name rk3568 --build-target hdf_test_audio

# 静态分析
cppcheck --enable=all --error-exitcode=1 hdi_service/ hal/ effect/ audio_dfx/ 2>/dev/null || true
clang-format --dry-run --Werror interfaces/include/ hdi_service/ hal/ effect/ 2>/dev/null || true
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建音频 HDI + 同步构建 `drivers/interface/audio` + 跑 `test/unittest/` + 运行 API 兼容性检查（`idl-check` 对比新旧 IDL） + 静态分析 |
| 音效功能 | `--gn-args="drivers_peripheral_audio_feature_effect=true"` 重新构建 + 静态分析 |
| HAL 适配 | 真机音频播放/录音验证 + 静态分析 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 + 静态分析 |
| DFX 变更 | 验证 hicollie/hitrace/hisysevent 埋点输出 + 静态分析 |

### Done 定义

- 构建通过（`drivers_peripheral_audio` + 测试目标）
- 无新增编译警告
- 无 lint/static analysis 违规（cppcheck/clang-format）
- 变更范围与任务要求一致
- 特性开关变更已同步 `audio.gni` + `bundle.json`
- VDI 接口变更已同步 `drivers/interface/audio` IDL
- DFX 埋点覆盖新增音频路径
- API 兼容性检查通过（涉及 IDL 变更时）

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果（含 lint/static analysis 结果）
3. 是否触发跨层同步修改（`drivers/interface/audio` IDL / `hdi_service/` 实现 / `bundle.json` / `audio.gni` / 下游 audio_service）
4. 是否影响特性开关默认值或公共 ABI
5. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/audio` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。
