# sensor多客户端能力测试2

> 本测试用例模拟五上游服务订阅sensor的情况。<br>
> 服务1，通过SetBatch(acc传感器, 200毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务2，通过SetBatch(acc传感器, 100毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务3，通过SetBatch(acc传感器, 50毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务4，通过SetBatch(acc传感器, 20毫秒采样频率, 废弃参数)的方式订阅。<br>
> 服务5，通过SetBatch(acc传感器, 10毫秒采样频率, 废弃参数)的方式订阅。<br>
> 最终期望的效果是：2秒时间内：
> 服务1，收到10帧数据，由于数据波动，在5-15之间可认为正常。
> 服务2，收到20帧数据，由于数据波动，在10-30之间可认为正常。
> 服务3，收到40帧数据，由于数据波动，在20-60之间可认为正常。
> 服务4，收到100帧数据，由于数据波动，在50-150之间可认为正常。
> 服务5，收到200帧数据，由于数据波动，在100-300之间可认为正常。

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
hdc file send SensorSetBatchTest1 /data/SensorSetBatchTest1
hdc file send SensorSetBatchTest2 /data/SensorSetBatchTest2
hdc file send SensorSetBatchTest3 /data/SensorSetBatchTest3
hdc file send SensorSetBatchTest4 /data/SensorSetBatchTest4
hdc file send SensorSetBatchTest5 /data/SensorSetBatchTest5
hdc shell chmod 777 /data/SensorSetBatchTest1
hdc shell chmod 777 /data/SensorSetBatchTest2
hdc shell chmod 777 /data/SensorSetBatchTest3
hdc shell chmod 777 /data/SensorSetBatchTest4
hdc shell chmod 777 /data/SensorSetBatchTest5

start cmd /k "hdc shell /data/SensorSetBatchTest1"
start cmd /k "hdc shell /data/SensorSetBatchTest2"
start cmd /k "hdc shell /data/SensorSetBatchTest3"
start cmd /k "hdc shell /data/SensorSetBatchTest4"
start cmd /k "hdc shell /data/SensorSetBatchTest5"
parse