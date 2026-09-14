# AGENTS.md - OpenHarmony 串口外设驱动（Drivers Peripheral Serial）

## 1. 代码地图

本目录实现原生 UART 串口 HDI 服务（`drivers_peripheral_serial` v7.0），通过 `drivers/interface/serial` 的 IDL 生成 proxy 调用本仓 stub。仅适配 `standard` 系统。

> **不要与 `usb/serial/` 混淆**：本目录是原生 UART 串口 HDI 服务；`usb/serial/` 是 USB-ACM 转串口 demo（属于 `drivers_peripheral_usb` 组件）。

### 关键区域

| 路径 | 职责 |
|------|------|
| `include/` | 内部头文件：`serial_service.h`、`serial_device.h`、`serial_device_manager.h`、`serial_device_callback.h`、`serial_hcb_util.h`、`serial_uevent_handle.h`、`serial_uevent_queue.h`、`serial_consts.h` |
| `src/` | 实现源码：`serial_service.cpp`（**高风险**：HDI stub，passthrough 模式下签名变更直接影响调用方）、`serial_device.cpp`（设备抽象）、`serial_device_manager.cpp`（设备管理）、`serial_device_callback.cpp`（数据上报回调）、`serial_hcb_util.cpp`（**高风险**：HCB 数据帧格式，变更影响协议兼容）、`serial_uevent_handle.cpp` + `serial_uevent_queue.cpp`（uevent 热插拔检测）、`serial_driver.cpp`（HDF 驱动入口） |
| `test/` | `unittest/`、`fuzztest/`、`benchmarktest/`、`sample/` |

### 架构分层

```
上层（serial_service / 应用）
  └─ proxy（由 drivers/interface/serial IDL 生成）
      ↓ passthrough（innerapi_tags = ["passthrough"]，不走 IPC）
Serial HDI Service（src/serial_service.cpp）
  ├─ SerialDeviceManager（设备管理 + uevent 热插拔）
  └─ SerialDevice（设备抽象 + 数据读写）
      ↓
硬件 UART 驱动（/dev/tty*，通过 uevent 上报）
```

## 2. 知识路由

| 任务类型 | 先看哪里 |
|----------|----------|
| 串口接口实现 | `src/serial_service.cpp` + `include/serial_service.h` |
| 设备管理/热插拔 | `src/serial_device_manager.cpp` + `src/serial_uevent_handle.cpp` |
| 设备数据读写 | `src/serial_device.cpp` + `include/serial_device.h` |
| 数据上报回调 | `src/serial_device_callback.cpp` |
| HDF 驱动入口 | `src/serial_driver.cpp` |
| 特性开关 | `bundle.json` 的 `features`（无独立 `.gni` 文件） |
| 测试 | `test/unittest/` + `test/fuzztest/` |

### 词汇路由

| 术语/关键词 | 含义 | 先读 |
|-------------|------|------|
| HDI | Hardware Device Interface，驱动统一接口 | `drivers/interface/serial/` IDL 定义 |
| IDL | Interface Definition Language，HDI 接口描述文件 | `drivers/interface/serial/` 下 `.idl` 文件 |
| hdi-gen | IDL 编译器，自动生成 proxy/stub 代码 | 生成产物在 `drivers/interface/serial/` 产出目录 |
| passthrough | 非 IPC 模式，调用方直接加载共享库，不走 IPC | `BUILD.gn:44` 的 `innerapi_tags = ["passthrough"]` |
| innerapi_tags | OHOS 构建系统内部 API 标签，控制库的暴露方式 | `BUILD.gn:44` |
| HCB | Host Communication Block，串口数据帧格式 | `include/serial_hcb_util.h` + `src/serial_hcb_util.cpp` |
| uevent | Linux 内核设备热插拔事件机制 | `src/serial_uevent_handle.cpp` |
| chipset_base_dir | 产物安装到芯片分区 | `BUILD.gn:45` 的 `install_images` |
| LOG_DOMAIN | hilog 日志域标识，本组件固定 `0xD002519` | `BUILD.gn:28` |
| Feature switch | `bundle.json` features 中的特性开关 | `bundle.json:16` |

### 路径触发路由

| 触发路径 | 先确认/先读 |
|----------|------------|
| 修改 `include/*.h` | 确认 IDL 同步状态；passthrough 模式下签名变更直接影响调用方，需接口评审 |
| 修改 `src/serial_service.cpp` | 确认接口签名与 `drivers/interface/serial` IDL 一致 |
| 修改 `src/serial_hcb_util.cpp` | 确认 HCB 数据帧格式变更的协议兼容性 |
| 修改 `src/serial_uevent_handle.cpp` | 确认非 Linux 环境下的设备枚举回退逻辑 |
| 修改 `BUILD.gn` 的 `innerapi_tags` | 需评估对调用方加载方式的影响 |
| 修改 `BUILD.gn` 的 `LOG_DOMAIN` | 需确认日志域规划，不影响故障归因 |
| 修改 `bundle.json` features | 必须确认 `features` 列表与实际开关一致 |

### 编辑前声明

编辑代码前，先声明以下三项：
1. 任务类型（接口变更 / 设备管理 / 数据读写 / 回调 / HCB 协议 / uevent / 特性开关 / 测试）
2. 已读文档或已确认的路径状态
3. 发现的约束（禁止事项、ask-before、安全边界）

## 3. 约束边界

### 特性开关

- 仅 1 个开关：`drivers_peripheral_serial_feature_model`（`bundle.json` features，无独立 `.gni`）
- 无 `inner_kits` 声明（库以 `innerapi_tags = ["passthrough"]` 方式暴露）
- 变更 `features` 需同步 `bundle.json`

### 陷阱

- **passthrough 模式**：`innerapi_tags = ["passthrough"]`，服务不走 IPC，调用方直接加载共享库。修改接口签名需评估调用方兼容性
- **uevent 热插拔**：设备发现依赖 Linux uevent，非 Linux 环境下设备枚举不工作
- **无 `.gni` 文件**：特性开关仅在 `bundle.json`，不要去找 `serial.gni`（那是 `usb/serial/` 的）
- **install_images = [ chipset_base_dir ]**：产物安装到 chipset 分区
- **LOG_DOMAIN=0xD002519**：hilog 域定义在 `BUILD.gn`，新增日志需沿用此域

### 禁止事项

- **不要直接修改 `drivers/interface/serial` 的 IDL 文件**：IDL 变更需走 HDI 接口评审
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**

### Ask before

- **修改公共 API 签名、错误码或生命周期语义** — passthrough 模式下调用方直接加载共享库，无 IPC 隔离缓冲，签名变更直接影响调用方，需用户确认并走 HDI 接口评审
- **修改 HCB 数据帧格式**（`src/serial_hcb_util.cpp`）— 需确认跨版本协议兼容性
- **修改 `innerapi_tags`**（`BUILD.gn:44`）— 需评估对调用方加载方式的影响
- **修改 `LOG_DOMAIN`**（`BUILD.gn:28`）— 需确认日志域规划不影响故障归因
- **向串口设备发送破坏性命令**（如强制 reset、波特率/数据位/停止位强制变更）— 需用户明确确认，避免设备异常

### 安全/设备边界

- **不得绕过设备权限检查**直接访问 `/dev/tty*`
- **不得删除或降级 hilog 日志和 hitrace 事件**
- **不得修改 `LOG_DOMAIN` 定义**除非有明确的日志域重新规划
- **不得修改 `innerapi_tags = ["passthrough"]`**除非评估了对调用方加载方式的影响
- **不得修改 `hdi-gen` 生成的 proxy/stub 协议字段**，协议变更须走 IDL 评审

## 4. 验证闭环

> **构建脚本不在本仓**：`./build.sh` 须在 **OpenHarmony 源码树根目录**执行。

```bash
# 构建串口驱动
./build.sh --product-name rk3568 --build-target drivers_peripheral_serial

# 构建测试
./build.sh --product-name rk3568 --build-target hdf_test_serial

# 静态分析
clang-format --dry-run --Werror include/ src/
cppcheck --enable=all --error-exitcode=1 src/
```

### 任务特定验证

| 任务类型 | 验证命令 |
|----------|----------|
| 接口变更 | 构建 `drivers_peripheral_serial` + `drivers_interface_serial`；比对 `include/*.h` 与 `drivers/interface/serial/` IDL 确认签名一致；跑 `test/unittest/` |
| 特性开关翻转 | 重新构建 + 验证 `bundle.json` features 同步 |
| passthrough 行为变更 | 确认调用方（serial_service/应用）加载方式不受影响；构建上层依赖组件确认无 ABI break |
| HCB 协议变更 | 跑 `test/unittest/` 中 HCB 相关用例确认数据帧解析正确 |

### Done 定义

1. 构建通过（`drivers_peripheral_serial` + `hdf_test_serial`）
2. 无 lint/clang-format 违规
3. 接口变更已同步 `drivers/interface/serial` IDL
4. 完成报告包含文件清单（`file:line`）+ 验证结果

### 无法验证时

构建环境不可用时，列出应执行的命令并说明预期结果，明确标注「未验证」。涉及 IDL 变更的，需人工复核 IDL 与实现匹配性。
