执行用例前需要先干掉sensorservice，方法:
hdc target mount & hdc shell "mv /system/lib64/libsensor_service.z.so /system/lib64/libsensor_service1.z.so"
然后重启手机，手机开机不要亮屏，啥都不要操作，直接执行测试用例
 
然后执行测试用例达到预期图片结果
 
# 执行方法：
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorHubDumpTest /data/SensorHubDumpTest
hdc shell chmod 777 /data/SensorHubDumpTest
 
start cmd /k "hdc shell /data/SensorHubDumpTest"
parse
 
 
反例：