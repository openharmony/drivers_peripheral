# AGENTS.md - OpenHarmony 传感器 HDI 外设驱动（Drivers Peripheral Sensor）

## 1. 代码地图

本仓库实现 OpenHarmony 传感器 HDI 外设驱动，提供 50+ 传感器类型的数据采集（加速度计、陀螺仪、磁力计、环境光、接近、气压、湿度等）、传感器插拔检测及传感器转换。核心架构边界是**上层 SensorService 通过 `drivers/interface/sensor` 的 IDL 生成的 proxy 调用本仓的 HDI service 实现，HAL 层对接厂商传感器硬件**。

### 非本项目维护的目录

以下目录属于其他团队或生成产物，不属于本项目维护范围，修改时请跳过：

- `drivers/interface/sensor/`：HDI IDL 接口定义（v3_0/v3_1 + convert/v1_0），由接口团队维护，本仓是实现方不要反向修改 IDL
- 由 `hdi-gen` 工具生成的 proxy/stub 代码（构建产物，不在本仓源码树中）
- `chipset/` 下各芯片厂商驱动：由芯片厂商维护，每种传感器类型独立适配，不要交叉混改

### 嵌套指引

本仓目前无嵌套 AGENTS.md / CLAUDE.md / rules / skills 文件。以下子目录可按需新建嵌套 AGENTS.md：

- `hdi_service_3.0/`：当前活跃 HDI 服务（v3_0/v3_1），可新建 `hdi_service_3.0/AGENTS.md` 聚焦服务 stub、传感器插拔检测
- `hdi_impl/`：HDI 实现层，可新建 `hdi_impl/AGENTS.md` 聚焦传感器操作核心逻辑
- `hal/`：传感器控制器，可新建 `hal/AGENTS.md` 聚焦 ioctl 命令、传感器通道
- `chipset/`：厂商芯片驱动，可按传感器类型新建 `chipset/accel/AGENTS.md` 等
- `utils/`：工具函数，可新建 `utils/AGENTS.md` 聚焦 HiTrace 集成

### 关键区域

- `interfaces/include/`：公共 C API 头文件，含 `sensor_if.h`（SensorInterface 结构体：GetAllSensors、Enable、Disable、SetBatch、SetMode、SetOption、Register、Unregister、ReadData）、`sensor_type.h`（40+ 传感器类型枚举、SensorInformation、SensorEvents）
- `interfaces/v1_0/`：VDI 接口头文件，含 `isensor_interface_vdi.h`、`isensor_callback_vdi.h`
- `hdi_service/`：旧版 HDI 服务实现（v1_0/v2_0 时代）
- `hdi_service_3.0/`：当前活跃 HDI 服务实现（v3_0/v3_1），含 `convert_sensor/` 子目录
- `hdi_impl/`：HDI 实现层（`sensor_impl.cpp/h`，传感器操作逻辑）
- `hal/`：硬件抽象层（`sensor_controller.h`、`sensor_manager.h`、`sensor_channel.h`、`sensor_dump.h`，ioctl 命令：ENABLE/DISABLE/SET_BATCH/SET_MODE/SET_OPTION/READ_DATA）
- `chipset/`：厂商传感器芯片驱动（按类型分组）：
  - `chipset/accel/`：BMI160、BMI270、MIC6200、MXC6655XA 加速度计
  - `chipset/als/`：BH1745、BH1750、MN7991X 环境光
  - `chipset/barometer/`：BMP180 气压计
  - `chipset/gyro/`：BMI160、BMI270、MIC6200 陀螺仪
  - `chipset/magnetic/`：LSM303、MMC5617 磁力计
  - `chipset/proximity/`：APDS9960、MN7991X 接近传感器
  - `chipset/humidity/`、`chipset/temperature/`、`chipset/gas/`、`chipset/hall/`、`chipset/pedometer/`、`chipset/ppg/`
- `utils/`：工具函数（`sensor_uhdf_log.h`、`sensor_trace.h` HiTrace 集成）
- `test/`：`unittest/`、`fuzztest/`（19 个）、`benchmarktest/`、`performance/`、`autotest/`、`common/`
- `sensor.gni`：4 个特性开关

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 传感器数据采集 | `hdi_impl/` + `hal/` + `interfaces/include/sensor_if.h` |
| 传感器插拔检测 | `hdi_service_3.0/` + `drivers/interface/sensor/v3_0/ISensorPlugCallback.idl` |
| HAL 适配 | `hal/` + `hal/include/sensor_controller.h` |
| 芯片驱动适配 | `chipset/<传感器类型>/` |
| 特性开关 | `sensor.gni` 的 `declare_args()` 段 |
| 传感器类型定义 | `interfaces/include/sensor_type.h`（SensorTypeTag 枚举） |
| HiTrace | `utils/include/sensor_trace.h` |
| 测试 | `test/unittest/` + `test/fuzztest/`（19 个）+ `test/autotest/` |

### 架构分层

```
上层（SensorService SA / miscservices）
  └─ proxy（由 drivers/interface/sensor IDL 生成）
      ↓ IPC
HDI Service
  ├─ hdi_service_3.0/（当前活跃，v3_0/v3_1）
  └─ hdi_service/（旧版，v1_0/v2_0 时代）
      ↓
HDI Impl（hdi_impl/sensor_impl.cpp）
      ↓
HAL（hal/）— 传感器控制器，ioctl 命令
      ↓
Chipset Drivers（chipset/）— 厂商传感器芯片
  ├─ accel/（BMI160/BMI270/MIC6200/MXC6655XA）
  ├─ gyro/（BMI160/BMI270/MIC6200）
  ├─ als/（BH1745/BH1750/MN7991X）
  ├─ magnetic/（LSM303/MMC5617）
  ├─ proximity/（APDS9960/MN7991X）
  └─ ...（barometer/gas/hall/humidity/pedometer/ppg/temperature）
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 新增/修改传感器接口 | `interfaces/include/` → `hdi_service_3.0/` → `drivers/interface/sensor` IDL |
| 传感器数据路径 | `hdi_impl/sensor_impl.cpp` → `hal/src/sensor_controller.c` → `hal/src/sensor_channel.c` |
| 新增芯片驱动 | `chipset/` 对应类型目录 + `hal/include/sensor_controller.h` |
| 传感器插拔 | `hdi_service_3.0/` + `drivers/interface/sensor/v3_0/ISensorPlugCallback.idl` |
| 传感器转换 | `hdi_service_3.0/convert_sensor/` + `drivers/interface/sensor/convert/` IDL |
| 特性开关变更 | `sensor.gni` + `bundle.json` |
| 测试修改 | `test/unittest/` + `test/fuzztest/` + `test/autotest/` + `test/benchmarktest/` |
| HiTrace 集成 | `utils/include/sensor_trace.h` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `interfaces/include/` | 公共 C API，变更需同步 `hdi_service_3.0/` 和下游 SensorService |
| `interfaces/v1_0/` | VDI 接口，版本化 |
| `hdi_service_3.0/` | **当前活跃服务**，对应 `drivers/interface/sensor/v3_0/` 和 `v3_1/` IDL |
| `hdi_service/` | **旧版服务**（v1_0/v2_0），非活跃，修改需谨慎 |
| `hdi_impl/` | HDI 实现层，传感器操作核心逻辑 |
| `hal/` | 传感器控制器（ioctl），厂商适配 |
| `chipset/` | 厂商传感器芯片驱动，按传感器类型分目录 |
| `sensor.gni` | 4 个特性开关，变更需同步 `bundle.json` |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| SensorTypeTag | 传感器类型枚举（ACCELEROMETER=1, GYROSCOPE=2, ...） | `interfaces/include/sensor_type.h` |
| SensorMode | 传感器模式（DEFAULT/REALTIME/ON_CHANGE/ONE_SHOT/FIFO_MODE） | `interfaces/include/sensor_type.h` |
| SensorInformation | 传感器信息（名称、供应商、版本、范围、精度等） | `interfaces/include/sensor_type.h` |
| SensorEvents | 传感器事件数据 | `interfaces/include/sensor_type.h` |
| PlugCallback | 传感器插拔回调，v3_0 新增 | `drivers/interface/sensor/v3_0/ISensorPlugCallback.idl` |
| Convert | 传感器转换接口，旧版适配 | `hdi_service_3.0/convert_sensor/` |
| Medical Sensor | 医疗传感器（类型 ID 128-160） | `interfaces/include/sensor_type.h` |
| SdcSensorInfo | SDC 传感器信息 | `interfaces/include/sensor_if.h` |
| TV Flag | TV 平台标志，影响特性可用性 | `sensor.gni` 中 `drivers_peripheral_sensor_feature_tv_flag` |
| Community | 社区版构建 | `sensor.gni` 中 `drivers_peripheral_sensor_feature_community` |

### 在计划阶段，必须声明

- **任务分类**（如：传感器接口变更 / 数据采集变更 / 传感器插拔 / 传感器转换 / 芯片驱动适配 / 特性开关变更 / HiTrace 集成 / 测试修改）
- **目标版本**（hdi_service_3.0 对应 v3_0/v3_1 / hdi_service 旧版），明确是否为活跃构建
- **目标 chipset 类型**（如涉及芯片驱动，明确传感器类型：accel/gyro/als/magnetic/proximity 等）
- **已读取的头文件和构建配置**（具体到文件路径）
- **发现的约束**（架构不变量、禁止事项、医疗传感器合规性、innerapi 标签、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 公共 API 变更 → 同步 `hdi_service_3.0/` 实现 + `drivers/interface/sensor` IDL + 下游 SensorService
  - VDI 接口变更 → 同步 `drivers/interface/sensor` 对应版本 IDL
  - 传感器类型变更 → 评估医疗传感器（类型 ID 128-160）权限和合规性
  - 特性开关变更 → 同步 `sensor.gni` + `bundle.json` features 列表
  - 新增芯片驱动 → 放在 `chipset/` 对应类型目录
  - HiTrace 变更 → 评估新路径的 trace 埋点覆盖

## 3. 约束边界

### 架构不变量

- **hdi_service_3.0 是当前活跃服务**：新功能在 v3_0/v3_1 上开发，hdi_service/ 是旧版
- **HDI service 是 IDL 的实现方**：接口定义在 `drivers/interface/sensor`
- **HAL 层通过 ioctl 对接硬件**：`sensor_controller.h` 定义了所有 ioctl 命令
- **chipset/ 是厂商芯片驱动**：每种传感器类型有独立子目录，不要交叉混改
- **医疗传感器**：类型 ID 128-160，有特殊权限要求
- **innerapi 标签**：v3_0 和 v3_1 标记为 chipsetsdk 和 platformsdk_indirect

### 禁止事项

- **不要直接修改 `drivers/interface/sensor` 的 IDL 文件**
- **不要在 `hal/` 中写框架业务逻辑**
- **不要在 `chipset/` 中交叉修改不同传感器类型**：每种类型独立适配
- **不要降级使用旧版 `hdi_service/`**：新功能应在 `hdi_service_3.0/` 开发
- **不要手改 `hdi-gen` 生成的 proxy/stub 代码**：应修改 `drivers/interface/sensor` 的 `.idl` 源文件后由构建系统重生成
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在 `hal/` 中写框架业务逻辑②修改 IDL 文件而非通过接口评审③在 `chipset/` 中交叉修改不同传感器类型④降级使用旧版 `hdi_service/`⑤医疗传感器类型变更不同步权限校验⑥新增芯片驱动不放对应类型目录

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 SensorService 兼容性影响
- **切换特性开关默认值**：确认 sensor.gni 中 tv_flag/community 开关翻转的影响
- **修改医疗传感器类型**：确认类型 ID 128-160 权限校验和合规性
- **修改 innerapi_tags**：确认芯片厂商和平台 SDK 团队影响

### 需确认后再修改

- **公共 API 头文件签名变更**：需评估下游 SensorService 兼容性
- **传感器类型枚举变更**：`SensorTypeTag` 是 ABI 契约
- **特性开关默认值翻转**：特别是 `tv_flag` 和 `community`
- **新增 chipset 驱动**：需确认芯片型号和适配接口

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改公共 API 签名**：确认下游 SensorService 兼容性影响
- **变更传感器类型枚举**：确认 `SensorTypeTag` ABI 契约影响，医疗传感器（类型 ID 128-160）需权限校验
- **降级使用旧版 `hdi_service/`**：确认新功能不应在 `hdi_service_3.0/` 开发
- **在 `chipset/` 中修改**：确认不交叉修改不同传感器类型
- **新增芯片驱动**：确认芯片型号和适配接口，放在 `chipset/` 对应类型目录
- **医疗传感器变更**：确认类型 ID 范围（128-160）和权限校验逻辑
- **删除 `convert_sensor/` 适配层**：确认旧版接口转换不再需要

### 项目特定陷阱

- **两套 HDI service 并存**：`hdi_service/`（旧版）和 `hdi_service_3.0/`（当前），修改前确认目标版本
- **convert 适配层**：`hdi_service_3.0/convert_sensor/` 提供旧版接口转换，不要删除
- **chipset 驱动命名**：以芯片型号命名（如 `bmi160`、`apds9960`），不要用通用名
- **HiTrace 集成**：`utils/include/sensor_trace.h` 提供 SENSOR_TRACE 宏，新路径需添加 trace 埋点
- **community 默认 true**

## 4. 验证闭环

### 最小验证

```bash
./build.sh --product-name rk3568 --build-target drivers_peripheral_sensor
./build.sh --product-name rk3568 --build-target hdf_test_sensor
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 接口变更 | 构建 sensor HDI + 同步构建 `drivers/interface/sensor` + 跑 `test/unittest/` |
| 芯片驱动适配 | 真机传感器数据验证 |
| 传感器插拔 | 跑 `test/unittest/` 插拔场景 |
| 特性开关翻转 | 重新构建全量 + 验证 `bundle.json` features 同步 |
| HiTrace | 验证 `utils/include/sensor_trace.h` 埋点输出 |

### 静态分析 / Lint

```bash
# 代码格式与静态检查
./build.sh --product-name rk3568 --build-target drivers_peripheral_sensor --lint
# 或使用项目 clang-format 检查
clang-format --dry-run --Werror interfaces/include/ hdi_service_3.0/ hdi_impl/ hal/ utils/ chipset/
```

### Done 定义

- 构建通过（`drivers_peripheral_sensor` + 19 个 fuzztest + 测试目标）
- 无新增编译警告
- 变更范围与任务要求一致
- 特性开关变更已同步 `sensor.gni` + `bundle.json`
- VDI 变更已同步 `drivers/interface/sensor` IDL
- 新增芯片驱动已放在 `chipset/` 对应类型目录
- HiTrace 埋点覆盖新增传感器路径

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果
3. 目标版本（hdi_service_3.0 对应 v3_0/v3_1 / 旧版 hdi_service）及是否为活跃构建
4. 是否触发跨层同步修改（`drivers/interface/sensor` IDL / `hdi_service_3.0/` 实现 / `bundle.json` / `sensor.gni` / 下游 SensorService）
5. 是否影响特性开关默认值、传感器类型枚举 ABI 或医疗传感器合规性
6. 是否触及架构不变量或需确认事项
7. 涉及医疗传感器的变更需额外说明合规性和权限校验评估
8. 涉及芯片驱动的变更需说明放置在 `chipset/` 对应类型目录

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。涉及 `drivers/interface/sensor` IDL 变更的，必须人工复核 IDL 与实现的匹配性并说明无法在沙箱验证的限制。涉及医疗传感器的变更，必须人工复核类型 ID 范围（128-160）和权限校验逻辑。
