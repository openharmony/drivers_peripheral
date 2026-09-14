# AGENTS.md - OpenHarmony 输入外设驱动（Drivers Peripheral Input）

## 1. 代码地图

本目录实现输入设备 HDI 服务（`drivers_peripheral_input` v4.0），对上层输入系统服务提供设备管理、事件上报、设备控制能力。适配 `standard` + `small` 系统。

### 三个 HDI 模块

| 模块 | 头文件 | 职责 |
|------|--------|------|
| Input Manager | `interfaces/include/input_manager.h` | 打开/关闭设备、获取设备列表与信息 |
| Input Reporter | `interfaces/include/input_reporter.h` | 注册/注销数据上报回调、事件包上报 |
| Input Controller | `interfaces/include/input_controller.h` | 电源状态、设备类型、芯片信息、手势模式、电容测试、扩展命令 |

### 关键区域

| 路径 | 职责 |
|------|------|
| `interfaces/include/` | 公共 C API 头文件：`input_manager.h`、`input_reporter.h`、`input_controller.h`、`input_type.h` |
| `hdi_service/` | HDI 服务实现（`input_interfaces_driver.cpp` 驱动入口 + `input_interfaces_impl.cpp` 服务实现） |
| `hal/` | HAL 层（`hdi_input`），厂商适配；`ohos_lite` 下为主要路径，standard 下受 `feature_model` 开关控制 |
| `udriver/` | Udriver 模型驱动（`hdi_input_udriver`），HDF 新驱动模型，受 `feature_udriver` 开关控制 |
| `ddk_service/` | HID DDK 服务（`hid_ddk_target`），受 `feature_support_ddk` 开关控制 |
| `utils/` | 公共工具 |
| `test/` | `unittest/`、`fuzztest/`、`benchmarktest/`、`common/` |

### 架构分层

```
上层（input_service / 多模输入）
  └─ proxy（由 drivers/interface/input IDL 生成）
      ↓ IPC
HDI Service（hdi_service/）
  ├─ hdi_input_service（standard 主路径）
  ├─ hdi_input（hal/，feature_model 时启用）
  ├─ hdi_input_udriver（udriver/，feature_udriver 时启用）
  └─ hid_ddk_target（ddk_service/，feature_support_ddk 时启用）
      ↓
硬件输入驱动（/dev/input/event*，触摸屏/键盘/鼠标等）
```

## 2. 知识路由

| 任务类型 | 先看哪里 |
|----------|----------|
| 输入接口实现 | `hdi_service/input_interfaces_impl.cpp` + `interfaces/include/*.h` |
| HDF 驱动入口 | `hdi_service/input_interfaces_driver.cpp` |
| HAL 适配（厂商） | `hal/`（`include/` + `src/`） |
| Udriver 模型 | `udriver/`（`include/` + `src/`） |
| HID DDK | `ddk_service/` |
| 特性开关 | `input.gni` 的 `declare_args()` |
| 测试 | `test/unittest/` + `test/fuzztest/` + `test/benchmarktest/` |

### 词汇路由

| 术语/关键词 | 含义 | 先读 |
|-------------|------|------|
| HDI | Hardware Device Interface，驱动统一接口 | `drivers/interface/input/` IDL 定义 |
| IDL | Interface Definition Language，HDI 接口描述文件 | `drivers/interface/input/` 下 `.idl` 文件 |
| hdi-gen | IDL 编译器，自动生成 proxy/stub 代码 | 生成的代码在 `drivers/interface/input/` 产出目录 |
| Inner_kit | 跨组件暴露的内部接口头文件 | `bundle.json` 的 `inner_kits` 段 |
| Feature switch | GN `declare_args` 特性开关 | `input.gni` |
| proxy/stub | IPC 通信两端，由 hdi-gen 生成 | `drivers/interface/input/` 生成产物 |
| access_token | 系统权限令牌，HDI service 鉴权依赖 | `bundle.json` deps 中的 `access_token` |

### 路径触发路由

| 触发路径 | 先确认/先读 |
|----------|------------|
| 修改 `interfaces/include/*.h` | 确认 IDL 同步状态；读取 `drivers/interface/input/` 对应 IDL |
| 修改 `hal/` | 确认 `feature_model` 开关状态；`hal/` 仅做硬件抽象 |
| 修改 `udriver/` | 确认 `feature_udriver` 开关状态；`input_device_manager.h` 为独立 inner_kit |
| 修改 `ddk_service/` | 确认 `feature_support_ddk` 开关状态 |
| 修改 `input.gni` 开关 | 必须同步 `bundle.json` 的 `features` 列表 |
| 修改 `hdi_service/` 鉴权逻辑 | 需安全评审，见约束边界 |

### 编辑前声明

编辑代码前，先声明以下三项：
1. 任务类型（接口变更 / HAL 适配 / Udriver / DDK / 特性开关 / 测试）
2. 已读文档或已确认的路径状态
3. 发现的约束（禁止事项、ask-before、安全边界）

## 3. 约束边界

### 特性开关

`input.gni` 声明（4 个开关，全部默认 false，`bundle.json` features 同步）：

| 开关 | 默认 | 作用 |
|------|------|------|
| `drivers_peripheral_input_feature_model` | false | 启用 HAL 路径（`hal:hdi_input`） |
| `drivers_peripheral_input_feature_udriver` | false | 启用 Udriver 模型（`udriver:hdi_input_udriver`） |
| `drivers_peripheral_input_feature_support_ddk` | false | 启用 HID DDK（`ddk_service:hid_ddk_target`） |
| `drivers_peripheral_input_feature_lite_support_test` | false | Lite 测试支持 |

### 构建路径差异

- **ohos_lite**：仅构建 `hal:hdi_input`（其余路径不编译）
- **standard**：主路径 `hdi_service:hdi_input_service`，其余 3 个组件按开关条件编译
- 4 个开关全部 false 时，standard 下仅 `hdi_input_service`，无 HAL/Udriver/DDK

### inner_kits

| inner_kit | 头文件 | 来源 |
|-----------|--------|------|
| `hal:hdi_input` | `input_controller.h`、`input_manager.h`、`input_reporter.h`、`input_type.h` | `interfaces/include/` |
| `udriver:hdi_input_udriver` | `input_device_manager.h` | `udriver/include/` |

### 陷阱

- **HAL vs HDI Service 两条路径**：`hal/` 是旧 HAL 路径，`hdi_service/` 是新 HDI 服务路径；standard 下默认走 HDI Service，HAL 需显式开 `feature_model`
- **Udriver 是独立 inner_kit**：`hdi_input_udriver` 暴露 `input_device_manager.h`（在 `udriver/include/`），与 `hdi_input` 暴露的头文件不同
- **`hilog_lite` 依赖**：本组件依赖 `hilog_lite`（lite 日志），是少数依赖 hilog_lite 的接口仓
- **`access_token` 依赖**：HDI service 鉴权依赖 access_token

### 禁止事项

- **不要直接修改 `drivers/interface/input` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**
- **不要在 `hal/` 中写框架业务逻辑**：HAL 只做硬件抽象
- 特性开关变更必须同步 `bundle.json` 的 `features` 列表

### Ask before

- **修改公共 API 签名、错误码或生命周期语义** — 需用户确认并走 HDI 接口评审
- **修改 IPC parcel 字段顺序或序列化格式** — 需确认跨版本兼容性
- **修改 access_token 鉴权逻辑** — 需安全评审
- **修改持久化数据格式（如设备配置文件）** — 需确认向后兼容
- **向硬件发送电源状态/电容测试等命令** — 需用户明确确认，避免破坏性设备操作

### 安全/设备边界

- **不得绕过 access_token 鉴权**使测试通过或简化逻辑
- **不得删除或降级 DFX 日志和 HiSysEvent 事件**
- **不得向 `/dev/input/event*` 发送破坏性命令**（如重置电源状态、强制电容测试）除非用户明确要求
- **不得修改 hdi-gen 生成的 proxy/stub 协议字段**，协议变更须走 IDL 评审

## 4. 验证闭环

> **构建脚本不在本仓**：`./build.sh` 须在 **OpenHarmony 源码树根目录**执行。

```bash
# 构建输入驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_input

# 构建测试
./build.sh --product-name rk3568 --build-target hdf_test_input

# 静态分析
clang-format --dry-run --Werror interfaces/ hdi_service/ hal/ udriver/ ddk_service/
cppcheck --enable=all --error-exitcode=1 hdi_service/ hal/ udriver/
```

### 任务特定验证

| 任务类型 | 验证命令 |
|----------|----------|
| 接口变更 | 构建 `drivers_peripheral_input` + `drivers_interface_input`；比对 `interfaces/include/*.h` 与 `drivers/interface/input/` IDL 确认签名一致；跑 `test/unittest/` |
| HAL 适配 | `--gn-args="drivers_peripheral_input_feature_model=true"` 重新构建 |
| Udriver 模型 | `--gn-args="drivers_peripheral_input_feature_udriver=true"` 重新构建 |
| HID DDK | `--gn-args="drivers_peripheral_input_feature_support_ddk=true"` 重新构建 |
| 特性开关翻转 | 重新构建 + 验证 `bundle.json` features 同步 |

### Done 定义

1. 构建通过（`drivers_peripheral_input` + `hdf_test_input`）
2. 无 lint/clang-format 违规
3. 特性开关变更已同步 `bundle.json`
4. 接口变更已同步 `drivers/interface/input` IDL
5. 完成报告包含文件清单（`file:line`）+ 验证结果

### 无法验证时

构建环境不可用时，列出应执行的命令并说明预期结果，明确标注「未验证」。涉及 IDL 变更的，需人工复核 IDL 与实现匹配性。
