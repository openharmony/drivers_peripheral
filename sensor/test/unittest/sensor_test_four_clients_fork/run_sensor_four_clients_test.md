hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorFourClientsClient1Test /data/SensorFourClientsClient1Test
hdc file send SensorFourClientsClient2Test /data/SensorFourClientsClient2Test
hdc file send SensorFourClientsClient3Test /data/SensorFourClientsClient3Test
hdc file send SensorFourClientsClient4Test /data/SensorFourClientsClient4Test
hdc shell chmod 777 /data/SensorFourClientsClient1Test
hdc shell chmod 777 /data/SensorFourClientsClient2Test
hdc shell chmod 777 /data/SensorFourClientsClient3Test
hdc shell chmod 777 /data/SensorFourClientsClient4Test

echo [Main] t=0s: 启动 Client1（间隔1s，运行14s）...
start cmd /k "hdc shell /data/SensorFourClientsClient1Test"
echo [Main] Client1 已启动

echo [Main] t=0s~2s: 等待 2 秒...
timeout /t 2 /nobreak >nul

echo [Main] t=2s: 启动 Client2（间隔100ms，运行10s）...
start cmd /k "hdc shell /data/SensorFourClientsClient2Test"
echo [Main] Client2 已启动

echo [Main] t=2s~4s: 等待 2 秒...
timeout /t 2 /nobreak >nul

echo [Main] t=4s: 启动 Client3（间隔10ms，运行6s）...
start cmd /k "hdc shell /data/SensorFourClientsClient3Test"
echo [Main] Client3 已启动

echo [Main] t=4s~6s: 等待 2 秒...
timeout /t 2 /nobreak >nul

echo [Main] t=6s: 启动 Client4（间隔5ms，运行2s）...
start cmd /k "hdc shell /data/SensorFourClientsClient4Test"
echo [Main] Client4 已启动

echo [Main] t=6s~8s: 等待 2 秒（Client4 将在 t=8s 时停止）...
timeout /t 2 /nobreak >nul

echo [Main] t=8s: Client4 应已停止

echo [Main] t=8s~10s: 等待 2 秒（Client3 将在 t=10s 时停止）...
timeout /t 2 /nobreak >nul

echo [Main] t=10s: Client3 应已停止

echo [Main] t=10s~12s: 等待 2 秒（Client2 将在 t=12s 时停止）...
timeout /t 2 /nobreak >nul

echo [Main] t=12s: Client2 应已停止

echo [Main] t=12s~14s: 等待 2 秒（Client1 将在 t=14s 时停止）...
timeout /t 2 /nobreak >nul

echo [Main] t=14s: Client1 应已停止

echo [Main] ============================================
echo [Main] SensorTestFourClientsFork 测试结束
echo [Main] ============================================

endlocal
