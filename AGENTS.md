# 外设驱动实现仓 — Agent 指引

面向在 OpenHarmony `drivers_peripheral` 仓（子系统 `hdf`，各外设 HDI 服务/HAL 实现）
工作的 OpenCode 智能体。本仓**只实现服务**，不含接口定义；接口定义在
`drivers_interface` 各对应仓。

> 嵌套指引：本仓内每个一级子模块目录下均设有 `AGENTS.md`，提供该模块的目录结构、
> 子目录说明、构建命令与导航。深度知识路由到子模块 `AGENTS.md`（见下方
> 「子模块导航」）。其中 `camera/` 目录另有极为详尽的 `AGENTS.md`，相机开发务必
> 先读该文件。

## 仓概述

此仓主要包含各外设器件驱动相关的 **HDI 服务实现、HAL 层、驱动模型及测试用例**，
根据模块划分不同目录。接口定义（`.idl`）在 `drivers_interface` 仓；本仓基于
生成的接口头文件实现服务逻辑与驱动入口，并发布为 HDF 用户态驱动。

**接口与实现分离原则**：
- 接口仓（`drivers_interface/<module>/`）= 只定义接口（`.idl` + `BUILD.gn`）。
- **本仓**（`drivers_peripheral/<module>/`）= 服务实现 + 驱动入口 + 测试用例。
- HDI 框架核心（`drivers/hdf_core/`）= 编译模板 `hdi.gni`、IPC/直通模式框架。
- VDI（Vendor Driver Interface）可由芯片/板级供应商提供于
  `device/board/<board>/<module>/`。

## 全局工作流

1. **接口定义**：在 `drivers/interface/<module>/vX_Y/` 下编写 `.idl`（由接口仓负责）。
2. **编译生成**：`interface("<module>")` 模板生成 C/C++ 接口头文件、客户端 proxy
   与服务端 stub 代码到 `out/<product>/gen/drivers/interfaces/<module>/`。
3. **实现服务**（**本仓职责**）：在 `drivers/peripheral/<module>/hdi_service/` 中
   继承生成的 `IFooInterfaceService` 头文件，实现接口逻辑，编译为
   `lib<module>_host_service_vX.Y.z.so`。
4. **驱动入口**：实现 `struct HdfDriverEntry`，编译为 `lib<module>_driver.z.so`，
   并在产品 hcs 配置（`device_info.hcs`）中声明服务。
5. **调用服务**：客户端依赖 `//drivers/interface/<module>/vX.Y:lib<module>_proxy_vX.Y`，
   通过 `IFoo::Get()` 获取客户端实例。

## 子模块导航

本仓每个一级子目录实现一个外设模块的 HDI 服务/HAL，并配有独立的 `AGENTS.md`。
按功能分组如下：

### 媒体与图形

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `audio` | 音频 | 声卡加载、播放/录音对象、场景与音量控制 | [audio/AGENTS.md](audio/AGENTS.md) |
| `distributed_audio` | 分布式音频 | 分布式音频 HDI 服务实现 | [distributed_audio/AGENTS.md](distributed_audio/AGENTS.md) |
| `camera` | 相机 | HDI/VDI 三层架构实现（另有详细 `AGENTS.md`） | [camera/AGENTS.md](camera/AGENTS.md) |
| `distributed_camera` | 分布式相机 | 分布式相机 HDI 服务实现 | [distributed_camera/AGENTS.md](distributed_camera/AGENTS.md) |
| `display` | 显示 | Composer/Buffer/HAL/图形加速 | [display/AGENTS.md](display/AGENTS.md) |
| `codec` | 编解码 | 媒体编解码驱动能力 | [codec/AGENTS.md](codec/AGENTS.md) |
| `format` | 媒体文件复用 | 媒体文件复用/解复用驱动能力 | [format/AGENTS.md](format/AGENTS.md) |
| `clearplay` | 清屏 (DRM) | ClearPlay HDI 服务实现 | [clearplay/AGENTS.md](clearplay/AGENTS.md) |

### 输入与交互

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `input` | 输入 | 设备管理、流控制、数据上报、DDK | [input/AGENTS.md](input/AGENTS.md) |
| `vibrator` | 振动马达 | 振动马达 HDI 接口与实现 | [vibrator/AGENTS.md](vibrator/AGENTS.md) |
| `light` | 指示灯 | 指示灯 HDI 服务与 hdi_impl 实现 | [light/AGENTS.md](light/AGENTS.md) |
| `midi` | MIDI | MIDI HDI 服务与 common 实现 | [midi/AGENTS.md](midi/AGENTS.md) |

### 传感器与感知

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `sensor` | 传感器 | 信息查询、启停、订阅、参数配置 | [sensor/AGENTS.md](sensor/AGENTS.md) |
| `motion` | 动作 | 动作识别 HDI 服务与实现 | [motion/AGENTS.md](motion/AGENTS.md) |
| `intelligent_voice` | 智能语音 | 智能语音引擎/触发，passthrough 实现 | [intelligent_voice/AGENTS.md](intelligent_voice/AGENTS.md) |
| `memorytracker` | 内存追踪 | 内存追踪 HDI 服务实现 | [memorytracker/AGENTS.md](memorytracker/AGENTS.md) |

### 电源与热管理

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `power` | 电源 | 电源管理 HDI 实现 | [power/AGENTS.md](power/AGENTS.md) |
| `battery` | 电池 | 电池信息查询与充电管理 | [battery/AGENTS.md](battery/AGENTS.md) |
| `thermal` | 温控 | 温控 HDI 实现，含 `thermal.yaml` 策略 | [thermal/AGENTS.md](thermal/AGENTS.md) |

### 通信与连接

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `wlan` | WLAN | HAL/驱动通道、WPA/Hostapd、芯片层 | [wlan/AGENTS.md](wlan/AGENTS.md) |
| `bluetooth` | 蓝牙 | audio/hci 子模块 | [bluetooth/AGENTS.md](bluetooth/AGENTS.md) |
| `nearlink` | 星闪 (NearLink) | dli/off_find 子模块 | [nearlink/AGENTS.md](nearlink/AGENTS.md) |
| `nfc` | NFC | NFC HDI 服务与 vendor_adaptor | [nfc/AGENTS.md](nfc/AGENTS.md) |
| `connected_nfc_tag` | 连接式 NFC 标签 | 连接式 NFC 标签 HDI 服务 | [connected_nfc_tag/AGENTS.md](connected_nfc_tag/AGENTS.md) |
| `secure_element` | 安全单元 | SE/SIM SE/vendor 适配 | [secure_element/AGENTS.md](secure_element/AGENTS.md) |
| `ethernet` | 以太网 | eth_client/eth_interfaces | [ethernet/AGENTS.md](ethernet/AGENTS.md) |
| `ril` | RIL 无线接口 | 通话/SIM/短彩信/搜网/蜂窝数据 | [ril/AGENTS.md](ril/AGENTS.md) |
| `location` | 定位 | AGNSS/Geofence/GNSS 子模块 | [location/AGENTS.md](location/AGENTS.md) |

### USB 与串行

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `usb` | USB | DDK/Gadget/SCSI/Serial，Host/Device 侧管理 | [usb/AGENTS.md](usb/AGENTS.md) |
| `serial` | 串口 | 串口 HDI 实现 | [serial/AGENTS.md](serial/AGENTS.md) |
| `partitionslot` | 分区槽 | 分区槽 HDI 服务与 HAL | [partitionslot/AGENTS.md](partitionslot/AGENTS.md) |

### 安全与认证

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `user_auth` | 用户认证 | 用户认证 HDI 服务实现 | [user_auth/AGENTS.md](user_auth/AGENTS.md) |
| `pin_auth` | PIN 码认证 | PIN 码认证 HDI 服务实现 | [pin_auth/AGENTS.md](pin_auth/AGENTS.md) |
| `face_auth` | 人脸认证 | 人脸认证 HDI 服务实现 | [face_auth/AGENTS.md](face_auth/AGENTS.md) |
| `fingerprint_auth` | 指纹认证 | 指纹认证 HDI 服务实现 | [fingerprint_auth/AGENTS.md](fingerprint_auth/AGENTS.md) |
| `huks` | 统一密钥管理 | HUKS 密钥服务 HDI 实现 | [huks/AGENTS.md](huks/AGENTS.md) |

### 其他

| 模块 | 中文名 | 说明 | Agent 指引 |
|------|--------|------|------------|
| `base` | 公共基础库 | buffer_handle、hdf_trace、进程配置 rc/cfg | [base/AGENTS.md](base/AGENTS.md) |
| `devhost` | 设备 Host 进程 | HDF 设备 Host 进程封装 | [devhost/AGENTS.md](devhost/AGENTS.md) |
| `low_power_player` | 低功耗播放器 | 低功耗播放器 VDI 实现 | [low_power_player/AGENTS.md](low_power_player/AGENTS.md) |

## 常见目录约定

本仓各模块目录通常包含以下结构（具体见各模块 `AGENTS.md`）：

| 目录/文件 | 说明 |
|-----------|------|
| `hdi_service/` | HDI 服务实现（对接上层 IPC/直通接口），核心业务逻辑所在 |
| `hal/` 或 `hal_c/` | HAL 层实现（硬件抽象层） |
| `hdi_impl/` | HDI 接口实现（部分模块使用此命名） |
| `interfaces/` | 对外接口头文件/定义 |
| `test/` | 测试用例（UT/HDLT） |
| `utils/` | 工具/公共代码 |
| `chipset/` | 芯片层实现（部分模块） |
| `bundle.json` | 部件清单：`sub_component`（构建入口）、`inner_kits`（跨部件接口）、`test` |
| `<module>.gni` | GN 配置文件，汇总构建变量与 feature 开关 |
| `BUILD.gn` | 编译入口脚本 |

## 构建命令

构建从**完整 OpenHarmony 源码树根目录**执行，**不**在本仓目录内执行。

### 标准编译单模块

```bash
cd ${OHOS_ROOT}  # 源码树根目录
./build.sh --product-name rk3568 --build-target drivers_peripheral_<module>
```

### 快速增量编译（仅修改源码时，跳过 GN gen）

```bash
cd ${OHOS_ROOT}
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 drivers_peripheral_<module>
```

### 快速重编译（修改了 GN 配置）

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_<module> --fast-rebuild
```

### 产物路径

```
out/<product>/hdf/drivers_peripheral_<module>/
```

典型库文件：
- `lib<module>_host_service_vX.Y.z.so` — HDI 服务实现库
- 接口库（来自 `drivers_interface`）：`lib<module>_proxy_vX.Y.z.so` / `lib<module>_stub_vX.Y.z.so`

## 约束与边界

### 不可破坏（Do not）

- **不要**修改本仓去实现接口定义——接口变更须在 `drivers_interface` 仓新增版本
  目录，不得直接改已发布 `.idl` 接口签名。
- **不要**让本仓的 HDI 实现与 `drivers_interface` 对应版本的接口签名不一致。
- **不要**手改生成文件：IDL 编译产出的 `*_proxy.h`、`*_stub.h`、
  `ifoo_interface.h` 等均在 `out/<product>/gen/` 下，生成器是唯一真源。
- **不要**在不设置 `install_enable = true` 的情况下期望 `ohos_executable` 进镜像。
- **不要**改 `bundle.json` 的 `inner_kits` 已有接口声明而不评估跨部件影响。
- **不要**将 VDI（板载驱动）实现混入本仓——VDI 属于 `device/board/` 供应商代码。

### 改动前必须请示（Ask before）

- 新增一个外设模块目录（涉及 `subsystem_config.json` 注册与部件声明）。
- 修改 `bundle.json` 的 `inner_kits`（跨部件接口）或 `sub_component`（构建入口）。
- 修改任一 `*.gni` 文件中的 feature 开关默认值。
- 任何影响产物 ABI 的改动（服务库导出符号变化）。

### 不变量（Invariants）

- **依赖方向**：本仓 import `drivers_interface` 与 `build`；`drivers_interface`
  **不**反向 import 本仓。
- **接口冻结**：已发布版本的 HDI 接口签名不可变；本仓实现须与之匹配。
- **部件模型**：模块进镜像须满足——有 `part_name`、在部件 `sub_component`
  （或被其依赖）、部件在产品部件列表中。
- **HCS 配置**：HDI 服务发布依赖产品 `device_info.hcs` 中声明 Host/Device/moduleName。

## 验证闭环

### 最小检查（任何实现改动后必跑）

1. **GN 生成**：`./build.sh --product-name rk3568 --build-only-gn`，确认不报错。
2. **模块编译**：
   `./build.sh --product-name rk3568 --build-target drivers_peripheral_<module>`。
3. **相关测试**：按各模块 `test/` 目录下的测试套运行。

### Done 定义

任务完成须满足：
1. 上述最小检查全部通过。
2. 未触碰「不可破坏」项；若改了 `inner_kits` 或 feature 开关，已说明兼容性影响。
3. 未手改任何生成文件。
4. HDI 实现与 `drivers_interface` 对应版本接口签名一致。

## 知识路由

| 任务 | 先读 |
|------|------|
| 实现一个 HDI 服务 | 对应模块 `AGENTS.md` + `drivers_interface/<module>/AGENTS.md` |
| 新增外设模块 | `README_zh.md`、`base/AGENTS.md`、对应模块 `AGENTS.md` |
| 编译/部署/调试 | 对应模块 `AGENTS.md` 的「构建与验证」段；相机另读 `camera/AGENTS.md` |
| 改 VDI（板载驱动） | `device/board/<board>/<module>/` 供应商代码 + 相机 `camera/AGENTS.md` 的 VDI 段 |
| 改 bundle.json / 部件模型 | `build/AGENTS.md`（部件模型四配置文件） |
| GN 模板/构建参数 | `build/AGENTS.md`（知识路由表） |

## 约定

- 文档主要为中文（`README_zh.md`）；各模块另有模块级 `README_zh.md`。
- 仓库托管于 Gitee（openharmony/drivers_peripheral）。
- 版权头：Huawei Device Co., Ltd.，Apache-2.0（多数文件）。
- 相机模块（`camera/`）已有独立的详尽 `AGENTS.md`，本仓 `camera/AGENTS.md` 仅作
  导航与概述，深入开发须读 `camera/AGENTS.md`。
