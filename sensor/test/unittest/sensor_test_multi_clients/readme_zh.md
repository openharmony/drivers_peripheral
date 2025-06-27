# sensor多客户端能力测试1

> 本测试用例模拟两个上游服务订阅sensor的情况。<br>
> 服务1，通过setbatch(acc传感器, 100毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务2，通过SetSdcSensor(acc传感器, enable, 200赫兹采样频率)的方式订阅。<br>
> 最终期望的效果是：搜索关键字setSaBatch打印可看出设置的上报频率为100000000，底软的上报频率为100毫秒/次，通过搜索日志关键字OnDataEvent.*sensorType1s打印的时间戳以及打印次数观察是否符合预期。

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

将两个用例编译好后，放到统一路径，在当前路径执行如下命令：

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorSetBatchTest /data/SensorSetBatchTest
hdc file send SensorSetSdcSensorTest /data/SensorSetSdcSensorTest
hdc shell chmod 777 /data/SensorSetBatchTest
hdc shell chmod 777 /data/SensorSetSdcSensorTest

start cmd /k "hdc shell /data/SensorSetBatchTest"
start cmd /k "hdc shell /data/SensorSetSdcSensorTest"
parse