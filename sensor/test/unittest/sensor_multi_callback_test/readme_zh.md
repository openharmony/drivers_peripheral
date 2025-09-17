# sensor多客户端能力测试2

> 本测试用例模拟一个上游服务订阅sensor的情况，统计每秒收到数据个数，参数可以在cmd命令中修改。<br>
> 服务1，通过SetBatch(acc传感器, 10毫秒采样频率, 废弃参数)的方式订阅。<br>
> 最终期望的效果是：每秒时间内：
> 服务1，收到100帧数据，由于数据波动，在50-150之间可认为正常。

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

将用例编译好后，放到统一路径，在当前路径执行如下命令：

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorDataVolumePerSecondTest /data/SensorDataVolumePerSecondTest
hdc shell chmod 777 /data/SensorDataVolumePerSecondTest
hdc shell "export testSensorType=1;export testSamplingInterval=10000000;export testPrintDataFlag=false;export testTestTime=20000;/data/SensorDataVolumePerSecondTest"
pause