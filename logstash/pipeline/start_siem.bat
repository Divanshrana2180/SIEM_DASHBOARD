@echo off  
echo ==========================================  
echo    SIEM Dashboard - Auto Start Script  
echo ==========================================  
echo.  
  
cd /d D:\siem-dashboard  
  
echo [1/4] Starting Docker containers...  
start "Docker SIEM" cmd /k "docker-compose up -d && echo. && echo Docker containers started! && echo Press any key to close this window... && pause > nul"  
  
echo [2/4] Waiting for Elasticsearch to initialize (30 seconds)...  
timeout /t 30 /nobreak > nul  
  
echo [3/4] Starting Log Generator...  
start "Log Generator" cmd /k "python log_generator.py"  
  
echo [4/4] Opening Kibana Dashboard...  
timeout /t 5 /nobreak > nul  
start http://localhost:5601/app/dashboards  
  
echo.  
echo ==========================================  
echo    SIEM System Started Successfully!  
echo ==========================================  
echo.  
echo Services:  
echo   - Elasticsearch: http://localhost:9200  
echo   - Kibana:        http://localhost:5601  
echo   - Log Generator: Running in separate window  
echo.  
echo Press any key to close this starter window...  
pause > nul  