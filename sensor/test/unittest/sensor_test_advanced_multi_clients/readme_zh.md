# sensor高级多客户端并发测试

> 本测试用于验证sensor模块在多客户端同时访问不同传感器时的并发性能和稳定性。<br>
> 通过模拟4个客户端同时访问传感器，每个客户端设置不同的采样频率。<br>
> 测试时长为3秒。

---

## 目录

- [概述](#概述)
- [测试场景](#测试场景)
- [安装说明](#安装说明)
- [使用示例](#使用示例)
- [预期结果](#预期结果)
- [验证说明](#验证说明)

---

## 概述

本测试旨在验证sensor服务在多客户端并发访问场景下的性能表现和资源管理能力。测试将模拟4个独立的客户端进程同时访问同一个传感器，每个客户端配置不同的采样间隔，验证系统能够正确地为每个客户端提供符合预期频率的数据流。

---

## 测试场景

### 客户端配置

| 客户端 | 采样间隔 | 预期数据量 (3秒) | 数据范围 |
|--------|----------|------------------|----------|
| 客户端1 | 100ms (100000000ns) | 约30帧 | 15-45帧 |
| 客户端2 | 50ms (50000000ns) | 约60帧 | 30-90帧 |
| 客户端3 | 25ms (25000000ns) | 约120帧 | 60-180帧 |
| 客户端4 | 10ms (10000000ns) | 约300帧 | 150-450帧 |

---

## 安装说明

### 1. 编译测试程序

编译完成后，将可执行文件放到统一路径下，在当前路径执行以下命令：

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
```

### 2. 上传测试程序

```bash
hdc file send SensorSetBatchTest1 /data/SensorSetBatchTest1
hdc file send SensorSetBatchTest2 /data/SensorSetBatchTest2
hdc file send SensorSetBatchTest3 /data/SensorSetBatchTest3
hdc file send SensorSetBatchTest4 /data/SensorSetBatchTest4
hdc shell chmod 777 /data/SensorSetBatchTest1
hdc shell chmod 777 /data/SensorSetBatchTest2
hdc shell chmod 777 /data/SensorSetBatchTest3
hdc shell chmod 777 /data/SensorSetBatchTest4
```

---

## 使用示例

### 1. 启动多客户端并发测试

在Windows环境下，使用以下命令同时启动4个客户端：

```bash
start cmd /k "hdc shell /data/SensorSetBatchTest1"
ping -n 1 -w 100 127.0.0.1 > nul
start cmd /k "hdc shell /data/SensorSetBatchTest2"
ping -n 1 -w 100 127.0.0.1 > nul
start cmd /k "hdc shell /data/SensorSetBatchTest3"
ping -n 1 -w 100 127.0.0.1 > nul
start cmd /k "hdc shell /data/SensorSetBatchTest4"
```

### 2. 查看测试日志

```bash
hdc shell hilog -x > sensor_test.log
```

---

## 预期结果

### 成功标准

1. 所有4个客户端都能成功注册和启用传感器
2. 每个客户端收到的数据量在预期范围内
3. 没有出现内存泄漏或崩溃
4. 系统日志中没有严重错误信息

### 预期输出示例

```
[PASS] 3000ms get sensor data count is 32 (expected range: 15-45)  - 客户端1
[PASS] 3000ms get sensor data count is 58 (expected range: 30-90)  - 客户端2
[PASS] 3000ms get sensor data count is 125 (expected range: 60-180) - 客户端3
[PASS] 3000ms get sensor data count is 298 (expected range: 150-450) - 客户端4
```

---

## 验证说明

### 日志分析

通过解析日志验证测试结果：

```bash
# 统计每个客户端的数据回调次数
grep "OnDataEvent" sensor_test.log | grep "sensorType1" | wc -l
```

### 性能指标

1. **数据准确性**：每个客户端接收的数据量应在预期范围内
2. **资源占用**：CPU和内存占用应在合理范围内
3. **响应时间**：传感器数据上报延迟应满足采样间隔要求
4. **稳定性**：长时间运行不应出现性能下降或异常

---

## 注意事项

1. 确保设备已正确安装sensor驱动
2. 测试前请关闭其他可能使用sensor的应用
3. 测试过程中不要断开设备连接
4. 如出现异常，请检查设备日志以获取详细信息
5. 不同设备的sensor性能可能不同，预期结果需要根据实际设备特性调整

---

## 技术细节

### 测试流程

1. 每个客户端通过`Register`注册回调
2. 使用`SetBatch`设置采样间隔
3. 调用`Enable`启用传感器
4. 等待3秒收集数据
5. 调用`Disable`禁用传感器
6. 使用`Unregister`注销回调
7. 验证接收到的数据量

### 关键API

- `Register()` - 注册传感器回调
- `SetBatch()` - 设置采样间隔和批处理参数
- `Enable()` - 启用传感器
- `Disable()` - 禁用传感器
- `Unregister()` - 注销传感器回调

---

## 版本历史

- **v1.0** (2025) - 初始版本，支持4客户端并发测试
