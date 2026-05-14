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

echo [Main] t=0s: Starting Client1 (1s interval, runs 14s) ...
start cmd /k "hdc shell /data/SensorFourClientsClient1Test"
echo [Main] Client1 launched

echo [Main] t=0s~2s: waiting 2 seconds ...
timeout /t 2 /nobreak >nul

echo [Main] t=2s: Starting Client2 (100ms interval, runs 10s) ...
start cmd /k "hdc shell /data/SensorFourClientsClient2Test"
echo [Main] Client2 launched

echo [Main] t=2s~4s: waiting 2 seconds ...
timeout /t 2 /nobreak >nul

echo [Main] t=4s: Starting Client3 (10ms interval, runs 6s) ...
start cmd /k "hdc shell /data/SensorFourClientsClient3Test"
echo [Main] Client3 launched

echo [Main] t=4s~6s: waiting 2 seconds ...
timeout /t 2 /nobreak >nul

echo [Main] t=6s: Starting Client4 (5ms interval, runs 2s) ...
start cmd /k "hdc shell /data/SensorFourClientsClient4Test"
echo [Main] Client4 launched

echo [Main] t=6s~8s: waiting 2 seconds (Client4 will disable at t=8s) ...
timeout /t 2 /nobreak >nul

echo [Main] t=8s: Client4 should have disabled

echo [Main] t=8s~10s: waiting 2 seconds (Client3 will disable at t=10s) ...
timeout /t 2 /nobreak >nul

echo [Main] t=10s: Client3 should have disabled

echo [Main] t=10s~12s: waiting 2 seconds (Client2 will disable at t=12s) ...
timeout /t 2 /nobreak >nul

echo [Main] t=12s: Client2 should have disabled

echo [Main] t=12s~14s: waiting 2 seconds (Client1 will disable at t=14s) ...
timeout /t 2 /nobreak >nul

echo [Main] t=14s: Client1 should have disabled

echo [Main] ============================================
echo [Main] SensorTestFourClientsFork End
echo [Main] ============================================

endlocal
