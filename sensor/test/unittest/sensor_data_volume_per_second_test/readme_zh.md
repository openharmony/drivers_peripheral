# sensor��ͻ�����������1

> ����������ģ���������η�����sensor�������<br>
> ����1��ͨ��setbatch(acc������, 100�������Ƶ��, ��������)�ķ�ʽ���ġ�<br>
> ����2��ͨ��SetSdcSensor(acc������, enable, 200���Ȳ���Ƶ��)�ķ�ʽ���ġ�<br>
> ����������Ч���ǣ������ؼ���setSaBatch��ӡ�ɿ������õ��ϱ�Ƶ��Ϊ100000000���������ϱ�Ƶ��Ϊ100����/�Σ�ͨ��������־�ؼ���OnDataEvent.*sensorType1s��ӡ��ʱ����Լ���ӡ�����۲��Ƿ����Ԥ�ڡ�

---

## Ŀ¼

- [���](#���)
- [��װ˵��](#��װ˵��)
- [ʹ��ʾ��](#ʹ��ʾ��)
- [����](#����)
- [����֤](#����֤)

---

## ���
**ͼ 1**  Sensor��������ģ��ͼ<a name="fig1292918466322"></a>
![ʾ��ͼƬ](sensor_test.jpg)
---

## ����������Ҫ�죺

### 1. ��������

��������������ú󣬷ŵ�ͳһ·�����ڵ�ǰ·��ִ���������

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorDataVolumePerSecondTest /data/SensorDataVolumePerSecondTest
hdc shell chmod 777 /data/SensorDataVolumePerSecondTest
hdc shell "export testSensorType=1"
hdc shell "export testSamplingInterval=10000000"
hdc shell "export testPrintDataFlag=false"
hdc shell "export testTestTime=20"
hdc shell "/data/SensorDataVolumePerSecondTest"
parse