# sensor多客户端能力测试2

> 本测试用例模拟三上游服务订阅sensor的情况。<br>
> 服务1，通过SetBatch(acc传感器, 2毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务2，通过SetBatch(acc传感器, 20毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务3，通过SetSdcSensor(acc传感器, true, 10毫秒采样频率)的方式订阅。<br>
> 最终期望的效果是：2秒时间内：
> 服务1，收到1000帧数据，由于数据波动，在500-1500之间可认为正常。
> 服务2，收到100帧数据，由于数据波动，在50-150之间可认为正常。

---

## 目录

- [简介](#简介)
- [安装说明](#安装说明)
- [使用示例](#使用示例)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 简介
**图 1**  Sensor测试用例模拟图<a name="fig1292918466322"></a>
![示例图片](sensor_test.jpg)
---

## 运行用例的要领：

### 1. 编译用例

将五个用例编译好后，放到统一路径，在当前路径执行如下命令：

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorSetBatchTestSamplingInterval_2 /data/SensorSetBatchTestSamplingInterval_2
hdc file send SensorSetBatchTestSamplingInterval_20 /data/SensorSetBatchTestSamplingInterval_20
hdc file send SensorSetSdcSensorTestSamplingInterval_10 /data/SensorSetSdcSensorTestSamplingInterval_10
hdc shell chmod 777 /data/SensorSetBatchTestSamplingInterval_2
hdc shell chmod 777 /data/SensorSetBatchTestSamplingInterval_20
hdc shell chmod 777 /data/SensorSetSdcSensorTestSamplingInterval_10

start cmd /k "hdc shell /data/SensorSetBatchTestSamplingInterval_2"
ping -n 1 -w 100 127.0.0.1 > nul
start cmd /k "hdc shell /data/SensorSetBatchTestSamplingInterval_20"
ping -n 1 -w 100 127.0.0.1 > nul
start cmd /k "hdc shell /data/SensorSetSdcSensorTestSamplingInterval_10"
parse