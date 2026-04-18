hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SimulationGpsClient1Test /data/SimulationGpsClient1Test
hdc file send SimulationGpsClient2Test /data/SimulationGpsClient2Test
hdc file send SimulationGpsClient3Test /data/SimulationGpsClient3Test
hdc shell chmod 777 /data/SimulationGpsClient1Test
hdc shell chmod 777 /data/SimulationGpsClient2Test
hdc shell chmod 777 /data/SimulationGpsClient3Test

echo [Main] t=0s: Starting Client1 ...
start cmd /k "hdc shell /data/SimulationGpsClient1Test"
echo [Main] Client1 launched

echo [Main] t=0s~2s: waiting 2 seconds ...
timeout /t 2 /nobreak >nul

echo [Main] t=2s: Starting Client2 ...
start cmd /k "hdc shell /data/SimulationGpsClient2Test"
echo [Main] Client2 launched

echo [Main] t=2s~6s: waiting 4 seconds (Client2 runs 2s then disables) ...
timeout /t 4 /nobreak >nul

echo [Main] t=6s: Starting Client3 ...
start cmd /k "hdc shell /data/SimulationGpsClient3Test"
echo [Main] Client3 launched

echo [Main] t=6s~16s: waiting 10 seconds for all clients to finish ...
timeout /t 10 /nobreak >nul

echo [Main] ============================================
echo [Main] SimulationGpsGetDataTest End
echo [Main] ============================================

endlocal
