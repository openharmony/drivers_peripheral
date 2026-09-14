# AGENTS.md - OpenHarmony USB 外设驱动（Drivers Peripheral USB）

## 1. 代码地图

本目录实现 USB Host DDK 和 USB Device DDK（gadget 侧），提供用户态 USB 设备管理、配置、数据读写能力。上层通过 `drivers/interface/usb` 的 IDL 生成 proxy 调用本仓 HDI service 实现。

### 关键区域

| 路径 | 职责 |
|------|------|
| `interfaces/ddk/` | DDK 公共 C API 头文件，分 `host/`、`device/`、`common/` |
| `hdi_service/` | HDI 服务实现（USB Host/Device/Port 接口 stub），版本化服务 v1.2/v2.1/v2.0 |
| `ddk/` | DDK 核心实现，分 `host/`（Host DDK）和 `device/`（Device DDK），含 `libusb_pnp_manager` |
| `ddk_service/` | DDK Service（受 `drivers_peripheral_usb_feature_ddk_service` 开关控制，默认 true），分 `common/`、`usb_service/`、`scsi_service/`、`serial_service/` |
| `gadget/function/` | USB Device 侧功能驱动 demo：`acm/`（CDC-ACM 串口）、`ecm/`（CDC-ECM 网络）、`mtp/`（MTP）、`usbfn/`（USB Function 基础） |
| `serial/` | **USB ACM 串口驱动 demo**（`usbhost_acm`）+ Serial DDK 接口服务 v1.0。注意：这是 USB 转串口，与顶层 `drivers/peripheral/serial/`（原生 UART）是**不同组件** |
| `net/` | USB Host 侧网络驱动 demo：`libusbhost_ecm`（ECM）、`libusbhost_rndis_rawapi`（RNDIS） |
| `libusb_adapter/` | libusb（third_party）适配层 |
| `hdf_usb/` | HDF 驱动入口 |
| `cfg/` | 配置文件（`usb_etc_files`） |
| `utils/` | 公共工具 |
| `sample/` | 应用测试程序（Host/Device 侧 ACM 读写、速率测试） |
| `test/` | `unittest/`、`moduletest/`、`fuzztest/`、`benchmarktest/`、`performance/`、`UsbSubscriberTest/`、`UsbSubTest/` |

### 架构分层

```
上层（usb_service / multimedia / USB Manager）
  └─ proxy（由 drivers/interface/usb IDL 生成，版本 v1.2/v2.1/v2.0/v1.0）
      ↓ IPC
HDI Service（hdi_service/）
  ├─ USB Host 接口（v1.2）/ USB Device 接口（v2.1）/ USB Port 接口（v2.0）
  └─ Serial DDK 接口（v1.0，usb/serial/）
      ↓
DDK 核心（ddk/）+ DDK Service（ddk_service/，开关控制）
      ↓
libusb 适配（libusb_adapter/）→ 硬件 USB 驱动
```

### 版本化服务（inner_kits）

| inner_kit | 版本 | 路径 |
|-----------|------|------|
| `libusb_interface_service_1.2` | v1.2 | `hdi_service/` |
| `libusb_device_interface_service_2.1` | v2.1 | `hdi_service/` |
| `libusb_port_interface_service_2.0` | v2.0 | `hdi_service/` |
| `libserial_interface_service_1.0` | v1.0 | `serial/` |
| `libusb_pnp_manager` | - | `ddk/` |

> 版本号对应 `drivers/interface/usb` 的 IDL 版本。新增版本目录需确认版本号与 `bundle.json` 一致。

## 2. 知识路由

| 任务类型 | 先看哪里 |
|----------|----------|
| USB Host DDK 接口 | `interfaces/ddk/host/` + `ddk/host/` + `hdi_service/`（v1.2） |
| USB Device DDK 接口 | `interfaces/ddk/device/` + `ddk/device/` + `hdi_service/`（v2.1） |
| USB Port 管理 | `hdi_service/`（v2.0），`usbd_port.h`/`usbd_ports.h` |
| USB 转串口（ACM） | `serial/`（注意非顶层 `serial/`） |
| DDK Service | `ddk_service/`，受 `drivers_peripheral_usb_feature_ddk_service` 控制 |
| gadget 功能驱动 | `gadget/function/`（acm/ecm/mtp/usbfn） |
| 特性开关 | `usb.gni` 的 `declare_args()` |
| HiSysEvent | `hisysevent.yaml` + `hdi_service/include/usb_report_sys_event.h` |
| 测试 | `test/unittest/` + `test/fuzztest/`（fuzz 用 `libusb_proxy_1.2` + `libusb_serial_ddk_proxy_1.0`） |

### 词汇路由

| 术语/关键词 | 含义 | 先读 |
|-------------|------|------|
| HDI | Hardware Device Interface，驱动统一接口 | `drivers/interface/usb/` IDL 定义 |
| IDL | Interface Definition Language，HDI 接口描述文件 | `drivers/interface/usb/` 下 `.idl` 文件 |
| hdi-gen | IDL 编译器，自动生成 proxy/stub 代码 | 生成产物在 `drivers/interface/usb/` 产出目录 |
| DDK | Device Driver Kit，用户态 USB 驱动开发包 | `interfaces/ddk/` + `ddk/` |
| gadget | USB Device 侧功能驱动（设备模式） | `gadget/function/` |
| usbfn | USB Function 基础接口 | `gadget/function/usbfn/` |
| CDC-ACM | USB 串口通信抽象控制模型 | `serial/` + `gadget/function/acm/` |
| ECM | CDC-ECM，USB 以太网控制模型 | `net/libusbhost_ecm/` + `gadget/function/ecm/` |
| RNDIS | Remote Network Driver Interface Specification | `net/libusbhost_rndis_rawapi/` |
| MTP | Media Transfer Protocol | `gadget/function/mtp/` |
| passthrough | 透传模式，直接访问 USB 设备 | `usb.gni` 的 `usb_drivers_pass_through` |
| SCSI | USB 存储 SCSI 命令层 | `ddk_service/scsi_service/` |
| Inner_kit | 跨组件暴露的内部接口库 | `bundle.json` 的 `inner_kits` 段 |
| Feature switch | GN `declare_args` 特性开关 | `usb.gni` |
| access_token | 系统权限令牌，HDI service 鉴权依赖 | `bundle.json` deps 中的 `access_token` |

### 路径触发路由

| 触发路径 | 先确认/先读 |
|----------|------------|
| 修改 `interfaces/ddk/**/*.h` | 确认 IDL 同步状态；读取 `drivers/interface/usb/` 对应 IDL；此为公共 DDK API，需接口评审 |
| 修改 `hdi_service/` | 确认版本号（v1.2/v2.1/v2.0）与 `bundle.json` inner_kits 一致 |
| 修改 `hdi_service/` 鉴权逻辑 | 需安全评审，见约束边界 |
| 修改 `ddk/` | 确认 DDK 核心实现与 `interfaces/ddk/` 头文件签名一致 |
| 修改 `ddk_service/` | 确认 `drivers_peripheral_usb_feature_ddk_service` 开关状态 |
| 修改 `gadget/function/` | 确认对应功能（acm/ecm/mtp/usbfn）的 DDK 接口依赖 |
| 修改 `serial/` | 确认非顶层 `drivers/peripheral/serial/`（原生 UART） |
| 修改 `usb.gni` 开关 | 必须同步 `bundle.json` 的 `features` 列表 |
| 修改 `hisysevent.yaml` | 需确认 HiSysEvent 事件定义完整性，见约束边界 |

### 编辑前声明

编辑代码前，先声明以下三项：
1. 任务类型（接口变更 / DDK 实现 / DDK Service / gadget / 串口 / 网络 / 特性开关 / 测试）
2. 已读文档或已确认的路径状态
3. 发现的约束（禁止事项、ask-before、安全边界）

## 3. 约束边界

### 特性开关

`usb.gni` 声明（`bundle.json` features 列表仅含前 3 个，变更需同步）：

| 开关 | 默认 | 作用 |
|------|------|------|
| `drivers_peripheral_usb_feature_linux_native_model` | false | Linux 原生模型 |
| `drivers_peripheral_usb_feature_ddk_service` | true | DDK Service 编译（控制 `ddk_service/` 全部子组件） |
| `drivers_peripheral_usb_feature_emulator_mode` | false | 模拟器模式 |
| `libusb_enable` | true（ohos_lite 下 false） | libusb 适配层开关，lite 系统自动关闭 |
| `usb_hisysevent_enable` | true | HiSysEvent 埋点 |
| `usb_samgr_enable` | true | SAMGR 集成 |
| `usb_c_utils_enable` | true | c_utils 工具库开关 |
| `usb_drivers_pass_through` | true | passthrough 模式 |

### 禁止事项

- **不要直接修改 `drivers/interface/usb` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `.idl` 源文件后由构建系统重生成
- **不要混淆 `usb/serial/` 与顶层 `serial/`**：前者是 USB-ACM 转串口 demo，后者是原生 UART 串口 HDI 服务（独立组件 `drivers_peripheral_serial`）
- **不要在 community 构建中引入 rich_device 专属功能**
- 特性开关变更必须同步 `bundle.json` 的 `features` 列表

### Ask before

- **修改公共 DDK API 签名、错误码或生命周期语义**（`interfaces/ddk/**/*.h`）— 需用户确认并走 HDI 接口评审
- **修改 IPC parcel 字段顺序或序列化格式** — 需确认跨版本兼容性
- **修改 access_token 鉴权逻辑** — 需安全评审
- **修改持久化数据格式（如 USB 设备配置文件 `cfg/`）** — 需确认向后兼容
- **向 USB 设备发送破坏性命令**（如 reset/reconfigure/电源管理）— 需用户明确确认，避免设备损坏
- **新增/删除 inner_kit 版本** — 需确认版本号与 `bundle.json` 和 `drivers/interface/usb` IDL 同步
- **修改 `libusb` 依赖版本** — 需确认许可证兼容性和 ABI 兼容性

### 安全/设备边界

- **不得绕过 access_token 鉴权**使测试通过或简化逻辑
- **不得绕过 USB 设备权限检查**直接访问 `/dev/bus/usb/*`
- **不得删除或降级 HiSysEvent 事件和 `hisysevent.yaml` 配置**
- **不得向 USB 设备发送破坏性命令**（如强制 reset、reconfigure、电源关断）除非用户明确要求
- **不得修改 hdi-gen 生成的 proxy/stub 协议字段**，协议变更须走 IDL 评审
- **不得删除或弱化 DFX 日志和故障归因逻辑**

### 陷阱

- **`ddk_service/` 整体受单一开关控制**：`drivers_peripheral_usb_feature_ddk_service=false` 会移除全部 4 个 ddk_service 子组件
- **`libusb_enable` 在 ohos_lite 自动为 false**：lite 系统不走 libusb 路径
- **版本化 inner_kits**：5 个 inner_kit 各有独立版本号，新增版本目录需同步 `bundle.json`
- **fuzz 测试依赖 proxy**：`test/fuzztest/` 依赖 `libusb_proxy_1.2` 和 `libusb_serial_ddk_proxy_1.0`，需先构建 `drivers_interface_usb`

## 4. 验证闭环

> **构建脚本不在本仓**：`./build.sh` 不在 `drivers/peripheral/` 下，须在 **OpenHarmony 源码树根目录**执行。

```bash
# 构建 USB 驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_usb

# 构建测试
./build.sh --product-name rk3568 --build-target hdf_test_usb

# 静态分析
clang-format --dry-run --Werror interfaces/ hdi_service/ ddk/ ddk_service/ serial/ gadget/ 2>/dev/null || true
cppcheck --enable=all --error-exitcode=1 hdi_service/ ddk/ ddk_service/ 2>/dev/null || true
```

### 任务特定验证

| 任务类型 | 验证命令 |
|----------|----------|
| 接口变更 | 构建 `drivers_peripheral_usb` + `drivers_interface_usb`；比对 `interfaces/ddk/*.h` 与 `drivers/interface/usb/` IDL 确认签名一致；跑 `test/unittest/` |
| 鉴权变更 | 跑 `hdf_test_usb` 中 access_token 相关用例确认无回归 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |
| DDK Service 变更 | 确认 `drivers_peripheral_usb_feature_ddk_service=true` 构建 |
| fuzz 测试 | 先构建 `drivers_interface_usb`（proxy），再构建 `hdf_test_usb` |

### Done 定义

1. 构建通过（`drivers_peripheral_usb` + `hdf_test_usb`）
2. 无 lint/static analysis 违规（cppcheck/clang-format）
3. 特性开关变更已同步 `bundle.json`
4. 接口变更已同步 `drivers/interface/usb` IDL
5. 完成报告包含文件清单（`file:line`）+ 验证结果

### 无法验证时

构建环境不可用时，列出应执行的命令并说明预期结果，明确标注「未验证」。涉及 IDL 变更的，需人工复核 IDL 与实现匹配性。
