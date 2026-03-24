# Camera Agent - OpenHarmony 相机驱动模块开发指南

## 工作目录

```bash
OHOS_ROOT=<您的鸿蒙源码路径>
# 例如
# OHOS_ROOT=~/ws/ohos

CAMERA_ROOT=${OHOS_ROOT}/drivers/peripheral/camera
```

## 业务架构

### 三层架构概述

OpenHarmony 相机驱动框架采用**三层架构**设计：

```
┌─────────────────────────────────────────────────────────┐
│                    Camera Service                        │
│                    (Framework Layer)                     │
└─────────────────────────────────────────────────────────┘
                          │ HDI Interface
┌─────────────────────────────────────────────────────────┐
│                   HDI 实现层                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ hdi_impl    │  │ buffer_mgr  │  │ device_mgr  │     │
│  │ HDI 具体实现  │  │ Buffer 管理  │  │ 设备管理     │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │pipeline_core│  │   adapter   │  │    utils    │     │
│  │ Pipeline 核心 │  │  平台适配层  │  │  工具类     │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
                          │ VDI Interface
┌─────────────────────────────────────────────────────────┐
│              VDI 层 (Vendor Driver Interface)            │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  选择其一 (根据平台)                             │   │
│  ├─────────────────────────────────────────────────┤   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │  方案 A: 通用 VDI (PC/通用平台)          │   │   │
│  │  │  ┌───────────┐  ┌───────────┐  ┌──────┐│   │   │
│  │  │  │  v4l2     │  │usb_camera │  │common││   │   │
│  │  │  │ V4L2 适配  │  │USB+FFmpeg │  │公共  ││   │   │
│  │  │  └───────────┘  └───────────┘  └──────┘│   │   │
│  │  │  编译：drivers_peripheral_camera_feature_usb=true │
│  │  └─────────────────────────────────────────┘   │   │
│  ├─────────────────────────────────────────────────┤   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │  方案 B: 板载 VDI (RK/海思等芯片平台)    │   │   │
│  │  │  ┌─────────────────────────────────┐   │   │
│  │  │  │  camera_board_vdi_impl          │   │   │
│  │  │  │  (已集成 USB 相机支持)            │   │   │
│  │  │  └─────────────────────────────────┘   │   │
│  │  │  编译：默认 (无需额外参数)              │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                          │ Hardware
┌─────────────────────────────────────────────────────────┐
│              Camera Sensor / ISP / Hardware              │
└─────────────────────────────────────────────────────────┘
```

### 各层职责

#### 1. HDI 层 (Hardware Device Interface)

**位置**: `drivers/peripheral/camera/interfaces/`, `hdi_service/`

**职责**:
- 实现 OpenHarmony 相机标准**南向接口**
- 提供 IPC 模式和直通模式两种 HDI 实现
- 定义相机驱动对上层服务提供的驱动能力接口

**核心接口**:
| 接口 | 描述 |
|------|------|
| `ICameraHost` | 相机主机接口，管理设备枚举、打开/关闭、闪光灯控制 |
| `ICameraDevice` | 相机设备接口，控制单个相机设备 |
| `IStreamOperator` | 流操作接口，创建/配置/释放流，捕获图像 |
| `ICameraHostCallback` | 主机回调，上报设备状态变化 |
| `ICameraDeviceCallback` | 设备回调，上报错误和 metadata |
| `IStreamOperatorCallback` | 流回调，上报捕获状态和帧数据 |

**目录结构**:
```
interfaces/
├── hdi_ipc           # IPC 模式的 HDI 实现
├── hdi_passthrough   # 直通模式的 HDI 实现
└── include           # HDI 接口定义

hdi_service/
└── (HDI 服务实现)
```

#### 2. 驱动层/框架层 (HAL Layer)

**位置**: `drivers/peripheral/camera/hal/` (在 vdi_base 中实现)

**职责**:
- 对接 HDI 层的**控制流**和**数据流**转发
- 实现**数据通路**的搭建
- 管理相机各个硬件设备
- 实现 Pipeline 模型

**核心模块**:
| 模块 | 目录 | 功能 |
|------|------|------|
| HDI 实现 | `hal/hdi_impl/` | HDI 接口的具体实现 |
| Buffer 管理 | `hal/buffer_manager/` | 统一的 Buffer 管理 |
| 设备管理 | `hal/device_manager/` | 设备枚举、能力查询 |
| Pipeline 核心 | `hal/pipeline_core/` | Pipeline 核心代码 |
| 平台适配 | `hal/adapter/` | 平台适配层实现 |
| 工具类 | `hal/utils/` | Watchdog 等工具 |
| 测试代码 | `hal/test/` | HDI 接口测试用例 |

**关键流程**:
```
1. 初始化 CameraHost → ICameraHost::Get()
2. 设置回调 → SetCallback()
3. 获取设备列表 → GetCameraIds()
4. 获取设备能力 → GetCameraAbility()
5. 打开设备 → OpenCamera()
6. 创建流 → CreateStreams()
7. 配置流 → CommitStreams()
8. 捕获图像 → Capture()
9. 接收帧数据 → OnFrameShutter()
```

#### 3. VDI 层 (Vendor Driver Interface)

**位置**: `drivers/peripheral/camera/vdi_base/`

**职责**:
- **屏蔽底层芯片和 OS 差异**
- 支持**多平台适配**
- 提供设备级的具体实现
- 对接不同硬件平台 (V4L2/USB/板载)
- 由芯片/板级供应商提供具体实现

**名称说明**: VDI = Vendor Driver Interface (供应商驱动接口)

**平台选择**:
- **芯片平台 (RK/海思等)**: 使用板载 VDI，由芯片供应商提供，已集成 USB 支持
- **通用平台 (PC/其他)**: 使用通用 USB VDI，平台无关，V4L2+FFmpeg

**VDI 类型**:
| 类型 | 描述 | 编译参数 | 平台依赖 | USB 支持 |
|------|------|----------|----------|----------|
| **通用 USB VDI** | 通用 USB 相机驱动，使用 V4L2+FFmpeg | `drivers_peripheral_camera_feature_usb=true` | 无 | ✅ |
| **板载 VDI** | 特定板级的相机驱动实现 | 板级配置 | 是 (芯片供应商提供) | ✅ (内部集成) |

**核心模块**:
| 模块 | 目录 | 功能 | 平台依赖 |
|------|------|------|----------|
| V4L2 适配 | `vdi_base/v4l2/` | Linux V4L2 设备适配 | 否 |
| USB 相机 | `vdi_base/usb_camera/` | 通用 USB 相机实现 (V4L2+FFmpeg) | 否 |
| 公共模块 | `vdi_base/common/` | 各平台公共代码 | 否 |
| VDI 接口 | `vdi_base/interfaces/` | Vendor Driver Interface 定义 | 否 |
| 板载实现 | `device/board/*/camera/` | 特定板级的 VDI 实现 (供应商提供) | 是 |

**VDI 实现对比**:

**板载 VDI 实现示例** (RK3568):
```
device/board/hihope/rk3568/camera/vdi_impl/v4l2/
├── device_manager/      # 设备管理实现
├── pipeline_core/       # Pipeline 配置和核心
├── pipeline_config/     # Pipeline 配置
└── ipp_algo_example/    # ISP 算法示例
```

**通用 USB VDI 实现** (平台无关):
```
drivers/peripheral/camera/vdi_base/usb_camera/
├── device_manager/      # USB 设备管理 (枚举/热插拔)
├── buffer_manager/      # USB Buffer 管理
├── metadata_manager/    # USB 相机元数据管理
├── pipeline_core/       # USB Pipeline 核心
└── v4l2_adapter/        # V4L2 接口适配 + FFmpeg 解码
```

### 数据流和控制流

#### 控制流 (Control Path)
```
Camera Service
     │
     ▼
┌─────────────────┐
│  ICameraHost    │ ← SetCallback, OpenCamera, GetCameraIds
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ ICameraDevice   │ ← UpdateSettings, SetResultMode
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Pipeline Core   │ ← 配置 Pipeline 参数
└─────────────────┘
     │
     ▼
┌─────────────────┐
│   VDI Layer     │ ← 硬件特定配置
└─────────────────┘
     │
     ▼
   Hardware
```

#### 数据流 (Data Path)
```
Camera Sensor
     │
     ▼
┌─────────────────┐
│   VDI Layer     │ ← V4L2/USB 数据接收
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Buffer Manager  │ ← Buffer 管理和分配
└─────────────────┘
     │
     ▼
┌─────────────────┐
│  Pipeline Core  │ ← 图像处理 (ISP/3A)
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Stream Operator │ ← 流控制和捕获
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ IBufferProducer │ ← BufferQueue 传递
└─────────────────┘
     │
     ▼
Camera Service / Application
```

### 关键组件交互

```
┌──────────────────────────────────────────────────────────────┐
│                        应用层                                 │
│  Camera App / Camera Service                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ ICameraHost/ICameraDevice
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                        HDI 层                                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐     │
│  │Host Service│  │Device Stub │  │ Vendor Tag Service │     │
│  └────────────┘  └────────────┘  └────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ 内部接口
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                       驱动层 (HAL)                            │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │Device Manager│  │Buffer Manager│  │  Pipeline Core   │    │
│  └─────────────┘  └──────────────┘  └──────────────────┘    │
│         │                │                  │                │
│         └────────────────┼──────────────────┘                │
│                          │                                   │
│                   ┌──────┴──────┐                           │
│                   │   Adapter   │ ← 平台适配层               │
│                   └──────┬──────┘                           │
└───────────────────────────┼───────────────────────────────────┘
                            │ VDI Layer Interface
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              VDI 层 (Vendor Driver Interface)                │
│                                                              │
│  根据平台选择方案 A 或方案 B (二选一)                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  方案 A: 通用 VDI (PC/通用平台)                         │ │
│  │  ┌──────────┐  ┌──────────────────────────────────┐   │ │
│  │  │  V4L2    │  │  USB Camera (V4L2 + FFmpeg)      │   │ │
│  │  │  Adapter │  │  - 标准 V4L2 协议                 │   │ │
│  │  │          │  │  - FFmpeg 解码                    │   │ │
│  │  │          │  │  - 支持热插拔                    │   │ │
│  │  └──────────┘  └──────────────────────────────────┘   │ │
│  │  编译：drivers_peripheral_camera_feature_usb=true      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  方案 B: 板载 VDI (RK/海思等芯片平台)                   │ │
│  │  ┌─────────────────────────────────────────────────┐  │ │
│  │  │  Board-Specific VDI (RK3568/Hi3516/etc.)        │  │ │
│  │  │  - 芯片特定 ISP 集成                             │  │ │
│  │  │  - 板级 Pipeline 配置                           │  │ │
│  │  │  - 已集成 USB 相机支持 (无需额外编译参数)        │  │ │
│  │  └─────────────────────────────────────────────────┘  │ │
│  │  编译：默认 (无需额外参数)                             │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                            │
                            │ Hardware Interface
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                        硬件层                                 │
│  Camera Sensor │ ISP │ MIPI CSI │ USB Controller            │
└──────────────────────────────────────────────────────────────┘
```

## 代码仓依赖

| 路径 | 部件名 | 作用 |
|------|--------|------|
| `drivers/peripheral/camera` | `drivers_peripheral_camera` | 相机设备驱动 |
| `drivers/interface/camera` | `drivers_interface_camera` | 相机 HDI 接口 |
| `device/board/hihope/rk3568/camera/vdi_impl/v4l2` | `camera_board_vdi_impl` | 相机板载 VDI 实现 |

## 编译命令

### 推荐编译策略

根据修改内容选择合适的编译方式：

| 场景 | 编译命令 | 耗时 | 说明 |
|------|----------|------|------|
| **仅修改源码** | `ninja -C ...` | **几秒** | 最快，跳过 GN 和 Python 封装 |
| **修改 GN 配置** | `./build.sh --fast-rebuild` | ~1-2分钟 | 跳过 GN gen，重新解析依赖 |
| **GN 报错/首次编译** | `./build.sh` | ~3-5分钟 | 完整编译，包含 GN gen 阶段 |

### 快速编译（推荐，仅修改源码时使用）

**适用场景**: 仅修改 `.cpp/.h` 源码，未修改 `BUILD.gn` 等 GN 配置文件

```bash
cd ${OHOS_ROOT}
# 直接使用 ninja 编译，速度最快
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 drivers_peripheral_camera
```

**优势**:
- 速度最快，增量编译只需几秒
- 跳过 GN gen 阶段和 Python 封装层
- 直接调用 ninja 增量编译

**注意**: 如果编译报错（如找不到目标），说明 GN 配置需要重新生成，请回退到完整编译。

### 标准构建

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_camera
```

### 快速重编译（仅修改源码）

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_camera --fast-rebuild
```

### 指定 CPU 架构

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_camera --target-cpu arm64
```

### 启用 USB 相机支持

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_camera \
  --gn-args="drivers_peripheral_camera_feature_usb=true"
```

**说明**: 启用 `drivers_peripheral_camera_feature_usb=true` 后，将编译**通用 USB camera VDI 驱动**
- **平台无关**: 不依赖特定芯片平台，可在任何支持 USB 的设备上运行
- **通用 V4L2 协议**: 使用标准 V4L2 接口与 USB 相机通信
- **FFmpeg 解码**: 集成 FFmpeg 进行视频流解码
- **即插即用**: 支持 USB 相机热插拔

---

## 平台编译策略

根据不同平台选择合适的驱动编译方案：

### RK 平台 (RK3568/RK3588 等)

**编译板载驱动** (板载驱动内部已包含 USB 实现)：

```bash
cd ${OHOS_ROOT}
./build.sh --product-name rk3568 --build-target drivers_peripheral_camera
# 不需要额外启用 drivers_peripheral_camera_feature_usb
# 板载 VDI 实现已包含 USB 相机支持
```

**特点**:
- 板载 VDI 实现 (`camera_board_vdi_impl`) 已集成 USB 相机支持
- 使用芯片厂商优化的 ISP 和 Pipeline
- 支持板载 MIPI 相机 + USB 相机

### 其他平台 (PC/通用 Linux)

**编译通用 USB 相机驱动**：

```bash
cd ${OHOS_ROOT}
./build.sh --product-name <产品名> --build-target drivers_peripheral_camera \
  --gn-args="drivers_peripheral_camera_feature_usb=true"
```

**特点**:
- 使用通用 USB VDI 驱动 (`vdi_base/usb_camera`)
- 不依赖特定芯片平台
- 使用标准 V4L2 + FFmpeg 解码
- 适用于无板载 VDI 实现的平台

---

### 平台驱动选择对比

| 平台 | 驱动类型 | 编译参数 | VDI 实现 | USB 支持 |
|------|----------|----------|----------|----------|
| **RK3568/RK3588** | 板载驱动 | (默认) | `camera_board_vdi_impl` | ✅ (板载内集成) |
| **Hi3516/Hi3559** | 板载驱动 | (默认) | 海思板载实现 | ✅ (板载内集成) |
| **PC/通用 Linux** | 通用 USB 驱动 | `drivers_peripheral_camera_feature_usb=true` | `vdi_base/usb_camera` | ✅ (通用 VDI) |
| **其他 ARM 板** | 通用 USB 驱动 | `drivers_peripheral_camera_feature_usb=true` | `vdi_base/usb_camera` | ✅ (通用 VDI) |

---

## RK3568 USB 相机调试技巧

### 强制加载 USB 相机驱动的修改方法

如果需要在 RK3568 平台上强制启用 USB 相机功能（绕过 HCS 配置的设备发现机制），可以通过修改 `GetVdiLibList` 函数实现:

**修改位置**: `hdi_service/v1_0/src/camera_host_service.cpp`

**实现代码**:
```cpp
int32_t CameraHostService::GetVdiLibList(std::vector<std::string> &vdiLibList)
{
#if 1  // 启用下面的强加载逻辑
    CAMERA_LOGW("force to load vdi so: libcamera_external_usb_camera.so");
    std::vector<std::string>().swap(vdiLibList);
    vdiLibList.push_back("libcamera_external_usb_camera.so");
    return 0;
#endif
    // 原始代码...
}
```

**修改说明**:
- 此修改使相机系统在枚举可用的 VDI 库时优先返回 USB 相机驱动
- 绕过基于 HCS (Hardware Configuration Set) 文件的设备配置发现机制
- 确保 USB 相机驱动被优先使用而非板载相机驱动
- 适用于调试 USB 相机功能以及在只有 USB 相机连接的情况下使用

**操作步骤**:
1. 修改上述代码
2. 重新编译: `./build.sh --product-name rk3568 --build-target drivers_peripheral_camera`
3. 将 `libcamera_host_service_1.0.z.so` 推送至 `/system/lib/`: 
   ```bash
   hdc file send libcamera_host_service_1.0.z.so /data/local/tmp/
   hdc shell "mount -o remount,rw /system"
   hdc shell "cp /data/local/tmp/libcamera_host_service_1.0.z.so /system/lib/libcamera_host_service_1.0.z.so"
   ```
4. 重启相机服务: 
   ```bash
   hdc shell killall camera_host
   hdc shell killall camera_service
   ```

## 构建产物路径

### 相机驱动模块
```bash
${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_camera/
```

**核心库文件**：
- `libcamera_host_service_1.0.z.so`
- `libperipheral_camera_buffer_manager.z.so`
- `libperipheral_camera_device_manager.z.so`
- `libperipheral_camera_metadata_manager.z.so`
- `libperipheral_camera_pipeline_core.z.so`
- `libperipheral_camera_utils.z.so`
- `libperipheral_camera_v4l2_adapter.z.so`
- `libcamera_example_vendor_tag_impl.z.so`

**USB 相机VDI实现库**（需启用 `drivers_peripheral_camera_feature_usb=true`）：
- `libcamera_external_usb_camera.so` - USB 相机主模块
- `libusb_camera_buffer_manager.z.so` - USB Buffer 管理
- `libusb_camera_device_manager.z.so` - USB 设备管理 (枚举/热插拔)
- `libusb_camera_metadata_manager.z.so` - USB 相机元数据管理
- `libusb_camera_pipeline_core.z.so` - USB Pipeline 核心
- `libusb_camera_v4l2_adapter.z.so` - V4L2 接口适配 + FFmpeg 解码

### HDI 接口模块
```bash
${OHOS_ROOT}/out/rk3568/hdf/drivers_interface_camera/
```

**接口库**：
- `libcamera_proxy_1.{0-5}.z.so`
- `libcamera_stub_1.{0-5}.z.so`
- `libmetadata.z.so`
- `libbuffer_handle_sequenceable_1.0.z.so`
- `libcamera_vendor_tag_proxy_1.0.z.so`

### 板载 VDI 实现
```bash
${OHOS_ROOT}/out/rk3568/rockchip_products/rockchip_products/
```

**VDI 库**：
- `libcamera_device_manager.z.so`
- `libcamera_host_vdi_impl_1.0.z.so`
- `libcamera_ipp_algo_example.z.so`
- `libcamera_pipeline_config.z.so`
- `libcamera_pipeline_core.z.so`

## 部署到设备 (RK3568)

### 推送板载相机库

- 需要先通过查看camera_host进程的maps，确定so的推送路径。（system分区或者vendor分区）
```bash
# 挂载可写
hdc shell mount -o rw,remount /vendor
hdc shell mount -o rw,remount /

# 推送驱动库
cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_camera/
hdc file send libcamera_host_service_1.0.z.so /vendor/lib
hdc file send libperipheral_camera_buffer_manager.z.so /vendor/lib
hdc file send libperipheral_camera_device_manager.z.so /vendor/lib
hdc file send libperipheral_camera_metadata_manager.z.so /vendor/lib
hdc file send libperipheral_camera_pipeline_core.z.so /vendor/lib
hdc file send libperipheral_camera_utils.z.so /vendor/lib
hdc file send libperipheral_camera_v4l2_adapter.z.so /vendor/lib
hdc file send libcamera_example_vendor_tag_impl.z.so /vendor/lib

# 推送 VDI 库
cd ${OHOS_ROOT}/out/rk3568/rockchip_products/rockchip_products/
hdc file send libcamera_device_manager.z.so /vendor/lib
hdc file send libcamera_host_vdi_impl_1.0.z.so /vendor/lib
hdc file send libcamera_ipp_algo_example.z.so /vendor/lib
hdc file send libcamera_pipeline_config.z.so /vendor/lib
hdc file send libcamera_pipeline_core.z.so /vendor/lib

# 重启相机服务
hdc shell killall camera_host
sleep 3
hdc shell killall camera_service
sleep 3
hdc shell "ps -A | grep camera"
```

### 推送 USB 相机库

**重要**：USB 相机库需要推送到不同分区，请使用以下正确的推送路径：

```bash
# 挂载可写
hdc shell mount -o rw,remount /vendor
hdc shell mount -o rw,remount /system
hdc shell mount -o rw,remount /

cd ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_camera/

# 1. 推送 USB VDI 主模块到 /vendor/lib/
#    (camera_host 通过 dlopen 加载此库)
hdc file send libcamera_external_usb_camera.so /vendor/lib/

# 2. 推送 USB 子模块到 /system/lib/
#    (这些库被 camera_host 链接使用)
hdc file send libusb_camera_buffer_manager.z.so /system/lib/
hdc file send libusb_camera_device_manager.z.so /system/lib/
hdc file send libusb_camera_metadata_manager.z.so /system/lib/
hdc file send libusb_camera_pipeline_core.z.so /system/lib/
hdc file send libusb_camera_v4l2_adapter.z.so /system/lib/

# 重启相机服务
hdc shell killall camera_host
sleep 3
hdc shell killall camera_service
sleep 3
hdc shell "ps -A | grep camera"
```

**推送路径说明**：
| 库文件 | 推送路径 | 说明 |
|--------|----------|------|
| `libcamera_external_usb_camera.so` | `/vendor/lib/` | VDI 主模块，由 camera_host 动态加载 |
| `libusb_camera_*.z.so` | `/system/lib/` | 子模块，camera_host 启动时链接 |

**验证推送位置**：
```bash
# 检查 camera_host 实际加载的库路径
hdc shell "cat /proc/$(hdc shell pidof camera_host)/maps | grep usb_camera"
```

## 验证步骤

### 1. 检查编译产物
```bash
ls -la ${OHOS_ROOT}/out/rk3568/hdf/drivers_peripheral_camera/*.so
```

### 2. 检查设备库文件
```bash
hdc shell "ls -la /vendor/lib/*camera*.so"
```

### 3. 检查相机服务状态
```bash
hdc shell "ps -A | grep camera_host"
```

### 4. 查看相机日志
```bash
hdc shell hilog | grep -i camera_host
```

## 常见问题

### 查看设备是否已经连接
```bash
# 预取有返回设备sn列表
hdc list target
```

### 确定正确的推送路径
在推送.so文件之前，应当首先确定camera_host服务实际上从哪里加载这些库文件。

```bash
# 第一步：获取camera_host进程的PID
hdc shell "pidof camera_host"

# 第二步：检查该进程的内存映射，找出实际的.so路径
PID=$(hdc shell "pidof camera_host")
hdc shell "cat /proc/$PID/maps | grep camera_host_service"

# 示例输出可能如下，表示需要更新/system/lib/下的库，而非/vendor/lib/:
# f6080000-f6083000 r--p 00000000 b3:07 5453 /system/lib/libcamera_host_service_1.0.z.so
# f6083000-f608b000 r-xp 00002000 b3:07 5453 /system/lib/libcamera_host_service_1.0.z.so
```
这种方法可以确保我们将.so文件推送到正确的分区，因为某些服务可能加载位于`/system/lib`的库而不是`/vendor/lib`的库。

### 编译失败
- 检查 GN 配置：`./build.sh --product-name rk3568 --build-target drivers_peripheral_camera --gn-args="..."`
- 清理构建：`rm -rf out/rk3568` 后重新编译

### 推送失败
- 确保设备已连接：`hdc list targets`
- 确保分区可写：`hdc shell mount -o rw,remount /vendor`
- 注意某些库可能需要放到`/system/lib`：`hdc shell mount -o remount,rw /system`

### 服务启动失败
- 检查库依赖：`hdc shell "ldd /vendor/lib/libcamera_host_service_1.0.z.so"`
- 查看完整日志：`hdc shell hilog`

## 模块依赖关系

```
drivers_peripheral_camera
├── drivers_interface_camera (HDI 接口)
├── VDI 层
│   ├── camera_board_vdi_impl (板载 VDI，芯片供应商提供，可选)
│   └── usb_camera (通用 USB VDI，平台无关，需启用 feature)
└── vdi_base (VDI 基础框架)
    ├── v4l2 (通用 V4L2 适配)
    ├── common (公共模块)
    └── interfaces (VDI 接口定义)
```

**VDI 选择**:
- **RK/海思等芯片平台**: 使用板载 VDI 实现 (已集成 USB 支持)
- **PC/通用平台**: 使用通用 USB VDI 驱动 (平台无关)
- **不要同时启用**: 根据平台选择其一，避免冲突

---

## AI 开发最佳实践

### 使用子 Agent 处理编译任务

编译 OpenHarmony 相机驱动时会产生大量日志输出，建议使用**子 Agent**方式执行编译，避免污染主会话上下文。

**推荐方式** (子 Agent):
```
任务：编译相机驱动模块
要求：
1. 后台执行编译命令
2. 完成后汇总报告结果
3. 不实时输出编译日志
```

**优势**:
- ✅ 避免编译日志污染主会话上下文
- ✅ 保持主会话清爽，专注于架构和代码分析
- ✅ 子 Agent 独立处理耗时任务，异步执行
- ✅ 自动汇总编译结果，便于快速查看

**对比**:
| 方式 | 上下文污染 | 任务管理 | 结果呈现 |
|------|-----------|----------|----------|
| 主会话编译 | ❌ 大量日志 | ❌ 阻塞会话 | ❌ 需要手动整理 |
| 子 Agent 编译 | ✅ 仅接收结果 | ✅ 异步执行 | ✅ 自动汇总报告 |

**实际案例**:
- 相机驱动编译耗时约 3-5 分钟，输出数千行日志
- 使用子 Agent 后，仅接收最终汇总报告
- 主会话可继续分析架构、修改代码，不受编译影响

### 编译验证清单

编译完成后验证以下内容：
- [ ] 检查三层架构产物是否完整 (HDI/HAL/VDI)
- [ ] 确认 USB 相机库是否按预期编译
- [ ] 验证 CCache 命中率 (应 >90%)
- [ ] 检查编译产物大小是否合理

---

## Buffer Dump 调试功能

相机驱动支持通过 `hidumper` 工具 dump 各节点的 buffer 数据，用于分析图像处理流程中的数据问题。

### Dump 配置文件

创建 `dump.config` 配置文件：

```bash
cat > dump.config <<EOF
enableDQBufDump=true
enableUVCNodeBufferDump=true
enableUVCNodeConvertedBufferDump=true
enableExifNodeConvertedBufferDump=false
enableFaceNodeConvertedBufferDump=false
enableForkNodeConvertedBufferDump=false
enableRKFaceNodeConvertedBufferDump=false
enableRKExifNodeConvertedBufferDump=false
enableCodecNodeConvertedBufferDump=false
enableRKCodecNodeConvertedBufferDump=false
enableSreamTunnelBufferDump=true
enableMetadataDump=false
previewInterval=5
videoInterval=5
EOF
```

**配置项说明**：

通过修改配置项的 `true` 或 `false` 值，可以灵活控制需要 dump 的节点：

| 配置项 | 值 | 说明 | 生成文件类型 |
|--------|-----|------|-------------|
| `enableDQBufDump` | `true`/`false` | V4L2 DQBuffer 层 dump | `DQBuffer_*.jpeg` |
| `enableUVCNodeBufferDump` | `true`/`false` | UVC 节点输入 buffer dump | `UVCNode_*.yuv` |
| `enableUVCNodeConvertedBufferDump` | `true`/`false` | UVC 节点转换后 buffer dump | `UVCNodeConverted_*.yuv` |
| `enableExifNodeConvertedBufferDump` | `true`/`false` | Exif 节点转换后 dump | `ExifNode_*.yuv` |
| `enableFaceNodeConvertedBufferDump` | `true`/`false` | 人脸节点转换后 dump | `FaceNode_*.yuv` |
| `enableForkNodeConvertedBufferDump` | `true`/`false` | Fork 节点转换后 dump | `ForkNode_*.yuv` |
| `enableRKFaceNodeConvertedBufferDump` | `true`/`false` | RK 人脸节点转换后 dump | `RKFaceNode_*.yuv` |
| `enableRKExifNodeConvertedBufferDump` | `true`/`false` | RK Exif 节点转换后 dump | `RKExifNode_*.yuv` |
| `enableCodecNodeConvertedBufferDump` | `true`/`false` | Codec 节点转换后 dump | `CodecNode_*.yuv` |
| `enableRKCodecNodeConvertedBufferDump` | `true`/`false` | RK Codec 节点转换后 dump | `RKCodecNode_*.yuv` |
| `enableSreamTunnelBufferDump` | `true`/`false` | StreamTunnel 层 buffer dump | `BeforeFlushSurface_*.yuv` |
| `enableMetadataDump` | `true`/`false` | Metadata 数据 dump | `*.meta` |
| `previewInterval` | 数字 | 预览流 dump 间隔（帧数），如 `5` 表示每 5 帧 dump 一帧 | - |
| `videoInterval` | 数字 | 视频流 dump 间隔（帧数），如 `5` 表示每 5 帧 dump 一帧 | - |

**使用示例**：

1. **只 dump V4L2 原始数据**：
```bash
cat > dump.config <<EOF
enableDQBufDump=true
enableUVCNodeBufferDump=false
enableUVCNodeConvertedBufferDump=false
enableSreamTunnelBufferDump=false
previewInterval=1
videoInterval=1
EOF
```

2. **只 dump StreamTunnel 输出数据**：
```bash
cat > dump.config <<EOF
enableDQBufDump=false
enableUVCNodeBufferDump=false
enableUVCNodeConvertedBufferDump=false
enableSreamTunnelBufferDump=true
previewInterval=5
videoInterval=5
EOF
```

3. **Dump 所有节点数据**（注意：会生成大量文件）：
```bash
cat > dump.config <<EOF
enableDQBufDump=true
enableUVCNodeBufferDump=true
enableUVCNodeConvertedBufferDump=true
enableExifNodeConvertedBufferDump=true
enableFaceNodeConvertedBufferDump=true
enableForkNodeConvertedBufferDump=true
enableRKFaceNodeConvertedBufferDump=true
enableRKExifNodeConvertedBufferDump=true
enableCodecNodeConvertedBufferDump=true
enableRKCodecNodeConvertedBufferDump=true
enableSreamTunnelBufferDump=true
enableMetadataDump=true
previewInterval=10
videoInterval=10
EOF
```

### Dump 操作步骤

```bash
# 1. 设置 SELinux 为 permissive 模式
hdc shell setenforce 0

# 2. 发送配置文件到设备
hdc file send dump.config /data/local/tmp/dump.config

# 3. 重新挂载 /data 为读写
hdc shell mount -o rw,remount /data

# 4. 清理历史 dump 文件
hdc shell rm -f /data/local/tmp/*.yuv
hdc shell rm -f /data/local/tmp/*.jpeg
hdc shell rm -f /data/local/tmp/*.meta

# 5. 修改权限
hdc shell chmod -R 777 /data/local/tmp

# 6. 启动相机应用
hdc shell aa start -a com.ohos.camera.MainAbility -b com.ohos.camera
sleep 3

# 7. 开始 dump
echo "Starting camera dump..."
hdc shell "hidumper -s 5100 -a '-host camera_host -o'"

# 8. 等待 dump 采集（期间保持相机预览）
sleep 10

# 9. 停止 dump
hdc shell "hidumper -s 5100 -a '-host camera_host -e'"

# 10. 查看生成的 dump 文件
hdc shell ls -la /data/local/tmp/*.yuv /data/local/tmp/*.jpeg

# 11. 拉取文件到本地
mkdir -p ./dump_files
hdc file recv /data/local/tmp/*.yuv ./dump_files/
hdc file recv /data/local/tmp/*.jpeg ./dump_files/

# 12. 清理远程文件
hdc shell rm -f /data/local/tmp/*.yuv
hdc shell rm -f /data/local/tmp/*.jpeg
hdc shell rm -f /data/local/tmp/*.meta
```

### Dump 文件说明

**生成的文件类型**：
- `DQBuffer_*.jpeg` - V4L2 DQBuffer 层采集的原始数据（MJPEG 格式）
- `BeforeFlushSurface_*.yuv` - StreamTunnel 层传递给上层的 YUV 数据（NV21 格式）
- `UVCNode_*.yuv` - UVC 节点处理后的 YUV 数据

**文件命名规则**：
```
BeforeFlushSurface_captureId[3]_streamId[1]_width[160]_height[120]_timestamp.yuv
DQBuffer_captureId[3]_streamId[1]_width[160]_height[120]_timestamp.jpeg
```

### 查看 Dump 文件

**YUV 文件播放**（使用 FFmpeg）：
```bash
# NV21 格式，160x120 分辨率示例
ffplay -f rawvideo -pixel_format nv21 -video_size 160x120 \
  BeforeFlushSurface_captureId[3]_streamId[1]_width[160]_height[120]_*.yuv
```

**JPEG 文件查看**：
```bash
# 直接用图片查看器打开
eog DQBuffer_captureId[3]_streamId[1]_width[160]_height[120]_*.jpeg
```

### 完整 Dump 脚本

脚本已保存到工作目录，可直接使用：

```bash
# 执行 dump 脚本
cd /home/zhouge/camera_dump
./dump_camera.sh

# 查看生成的文件
ls -la ./tmp/
```

---

## RK3568 相机自动化测试流程

### 完整操作步骤

```bash
# 设置 HDC 路径
HDC=<您的HDC工具路径>

# 1. 唤醒设备
$HDC shell power-shell wakeup

# 2. 设置灭屏超时（6 分钟）
$HDC shell power-shell timeout -o 360000

# 3. 模拟上滑解锁（从屏幕中间滑到下方）
$HDC shell uinput -T -m 300 600 300 100 500

# 4. 打开相机应用
$HDC shell aa start -a com.ohos.camera.MainAbility -b com.ohos.camera

# 5. 等待相机启动并截图确认
sleep 3
# 使用 -f 参数指定截图保存路径
$HDC shell snapshot_display -f /data/local/tmp/camera_before.jpeg
$HDC file recv /data/local/tmp/camera_before.jpeg ./camera_before_photo.jpeg

# 6. 点击拍照按钮（屏幕底部中央，720x1280 分辨率）
$HDC shell uinput -T -c 360 1100

# 7. 等待拍照完成并截图
sleep 3
$HDC shell snapshot_display -f /data/local/tmp/camera_after.jpeg
$HDC file recv /data/local/tmp/camera_after.jpeg ./camera_after_photo.jpeg

# 8. 查看拍照日志确认
$HDC shell hilog -x | grep -E "Capture|Photo|capture" | tail -30

# 9. 查找并拉取拍摄的照片
$HDC shell find /storage/media/100 -name "*.jpg" 2>/dev/null
$HDC file recv /storage/media/100/local/files/Photo/16/IMG_*.jpg ./captured_photo.jpg
```

### 关键参数

| 项目 | 值 | 说明 |
|------|-----|------|
| 屏幕分辨率 | 720×1280 | RK3568 设备 |
| 快门按钮位置 | (360, 1100) | 底部中央 |
| 解锁滑动 | (300,600)→(300,100) | 上滑解锁 |
| 灭屏超时 | 360000ms | 6 分钟 |

### 照片存储路径

```
/storage/media/100/local/files/Photo/16/IMG_*.jpg
```

### 常用 uinput 命令

```bash
# 触摸点击
uinput -T -c <x> <y>

# 触摸滑动
uinput -T -m <x1> <y1> <x2> <y2> <smooth_time>

# 键盘输入
uinput -K -t "text"

# 鼠标点击
uinput -M -c 0
```

### 问题排查

1. **相机应用未启动**: 检查 `ps | grep camera` 确认进程
2. **拍照无响应**: 查看 `hilog -x | grep CAMERA` 日志
3. **照片未保存**: 检查 MediaLibrary 服务和存储权限

### 开启相机详细日志调试

开启相机驱动的详细日志，用于深度调试：

```bash
# 开启相机 domain 的 debug 日志 (0xD002513 对应 camera_hdi_service)
hdc shell "hilog -bD -D 0xD002513"

# 关闭 domain 流控（防止日志被限流）
hdc shell "hilog -Q domainoff"

# 关闭 PID 流控
hdc shell "hilog -Q pidoff"

# 关闭隐私打印保护（显示完整日志内容）
hdc shell "hilog -p off"
```

**日志级别说明**：
- `-bD`: 设置 buffer 日志级别为 DEBUG
- `-D 0xD002513`: 为指定 domain 开启 DEBUG 级别日志

**常用 domain ID**：
| Domain ID | 模块 |
|-----------|------|
| `0xD002513` | camera_hdi_service (相机 HDI 服务) |
| `0xD002501` | camera_service (相机服务) |
| `0xD002515` | metadata_service (元数据服务) |

**查看日志**：
```bash
# 查看相机详细日志
hdc shell hilog | grep -i camera

# 查看特定 domain 日志
hdc shell hilog | grep "0xD002513"
```

---

## 屏幕截图工具

### snapshot_display 命令详解

`snapshot_display` 命令用于捕获设备屏幕截图，支持指定输出路径和多种参数。

**基本用法**：
```bash
# 默认保存到 /data/local/tmp/snapshot_<timestamp>.jpeg
hdc shell snapshot_display

# 指定输出文件路径（推荐）
hdc shell snapshot_display -f /data/local/tmp/my_screenshot.jpeg

# 拉取到本地
hdc file recv /data/local/tmp/my_screenshot.jpeg ./local_screenshot.jpeg
```

**完整参数说明**：
```bash
snapshot_display [-i displayId] [-f output_file] [-w width] [-h height] [-t type] [-m]
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `-i displayId` | 指定显示设备 ID | `-i 0` |
| `-f output_file` | 指定输出文件路径 | `-f /data/local/tmp/screenshot.jpeg` |
| `-w width` | 指定输出宽度 | `-w 720` |
| `-h height` | 指定输出高度 | `-h 1280` |
| `-t type` | 指定输出格式类型 | `-t jpeg` |
| `-m` | 多显示器模式 | `-m` |

**使用示例**：

```bash
# 示例 1：基本截图并拉取到本地
hdc shell snapshot_display -f /data/local/tmp/screen.jpeg
hdc file recv /data/local/tmp/screen.jpeg ./screen.jpeg

# 示例 2：指定分辨率截图
hdc shell snapshot_display -f /data/local/tmp/screen_720p.jpeg -w 720 -h 1280

# 示例 3：指定显示设备（多屏场景）
hdc shell snapshot_display -i 0 -f /data/local/tmp/display0.jpeg
```

**注意事项**：
- 确保设备已连接且屏幕处于点亮状态
- 输出路径必须有写入权限（建议使用 `/data/local/tmp/`）
- 截图完成后及时拉取到本地，避免被后续截图覆盖

---

## USB 相机 UT 测试

### 测试概述

USB 相机驱动包含基于 googletest 的单元测试，用于验证驱动功能正确性。

**测试代码位置**: `drivers/peripheral/camera/test/ut/usb_camera/`

**测试类型**:
| 测试套件 | 文件 | 说明 |
|----------|------|------|
| UtestUSBCameraTest | usb_camera_test.cpp | 单相机功能测试（58个测试用例） |
| UtestUSBCameraTestMult | usb_camera_test_mult.cpp | 多相机并发测试（3个测试用例） |

### 编译 UT 测试

```bash
cd ${OHOS_ROOT}

# 快速编译（推荐）
prebuilts/build-tools/linux-x86/bin/ninja -w dupbuild=warn -C out/rk3568 camera_usb_test_ut

# 标准编译
./build.sh --product-name rk3568 --build-target camera_usb_test_ut
```

**编译产物**: `out/rk3568/tests/unittest/drivers_peripheral_camera/camera/camera_usb_test_ut`

### 推送并运行测试

```bash
# 1. 推送测试二进制到设备
hdc shell mount -o rw,remount /data
hdc file send out/rk3568/tests/unittest/drivers_peripheral_camera/camera/camera_usb_test_ut /data/local/tmp/
hdc shell chmod +x /data/local/tmp/camera_usb_test_ut

# 2. 运行所有测试（约 3-5 分钟）
hdc shell "cd /data/local/tmp && ./camera_usb_test_ut"

# 3. 运行指定测试
hdc shell "cd /data/local/tmp && ./camera_usb_test_ut --gtest_filter='UtestUSBCameraTest.camera_usb_0001'"

# 4. 列出所有测试
hdc shell "cd /data/local/tmp && ./camera_usb_test_ut --gtest_list_tests"
```

### 常用测试用例

| 测试用例 | 功能 | 耗时 | 备注 |
|----------|------|------|------|
| camera_usb_0001 | 热插拔检测 | ~9s | ⚠️ 需人工插拔相机 |
| camera_usb_0002 | Zoom 能力查询 | ~3ms | - |
| camera_usb_0003 | 连接类型查询 | ~3ms | - |
| camera_usb_0018 | 打开相机 | ~7s | - |
| camera_usb_mult_0001 | 双相机预览 | ~15s | ⚠️ 可能因资源冲突失败 |
| camera_usb_mult_0002 | 双相机预览+拍照 | ~23s | 推荐测试 |

### 测试注意事项

#### ⚠️ 1. 热插拔测试设计不合理

**问题**: camera_usb_0001 等待人工插拔（3次 x 3秒 = 9秒），不符合自动化测试原则。

**建议**: 
- 跳过此测试: `--gtest_filter='-UtestUSBCameraTest.camera_usb_0001'`
- 或在插入 USB 相机后直接运行其他测试

#### ⚠️ 2. 全局变量状态不共享

**问题**: `g_usbCameraExit` 只在 camera_usb_0001 中设置，跳过它会导致其他测试跳过。

**解决**: 确保 USB 相机已插入后直接运行其他测试，或修改测试框架使状态在 SetUp 中检测。

#### ⚠️ 3. 多相机并发限制

**问题**: mult_0001 可能失败（rc=-3），原因是 USB 带宽限制或资源冲突。

**分析**: 
- RK3568 USB 带宽有限，双相机同时 CommitStreams 可能冲突
- mult_0002（预览+拍照）通常能通过，资源占用较少

**建议**:
- 单相机测试优先
- 多相机测试根据硬件能力选择执行

#### ⚠️ 4. 设备节点权限

**问题**: 测试需要访问 /dev/video* 节点。

**检查**:
```bash
hdc shell "ls -la /dev/video*"
# 应显示 camera_host 用户有权限
```

#### ✅ 5. 推荐测试组合

**快速验证**（约 30 秒）:
```bash
hdc shell "cd /data/local/tmp && ./camera_usb_test_ut \
  --gtest_filter='UtestUSBCameraTest.camera_usb_0002:UtestUSBCameraTest.camera_usb_0003:UtestUSBCameraTest.camera_usb_0018'"
```

**完整测试**（跳过热插拔，约 5 分钟）:
```bash
hdc shell "cd /data/local/tmp && ./camera_usb_test_ut \
  --gtest_filter='-UtestUSBCameraTest.camera_usb_0001:UtestUSBCameraTestMult.*'"
```

### 测试结果解读

| 结果 | 含义 | 处理建议 |
|------|------|----------|
| [  PASSED  ] | 测试通过 | ✅ 正常 |
| [  FAILED  ] | 测试失败 | ⚠️ 检查日志，分析失败原因 |
| [  SKIPPED ] | 测试跳过 | ℹ️ 通常因 USB 相机未插入 |

**常见失败原因**:
- rc=-3: CommitStreams 失败（资源冲突或配置不支持）
- rc=-4: OpenCamera 失败（设备被占用或权限问题）
- Skip: USB 相机未插入或全局变量未设置

---

*遵循本指南，保持专业高效的相机驱动开发*
