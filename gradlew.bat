@echo off
setlocal
set "APP_HOME=%~dp0"
rem Strip the trailing backslash. Otherwise the quoted --project-dir argument can be
rem parsed incorrectly by the Windows Java command-line parser (Invalid file path).
set "APP_HOME=%APP_HOME:~0,-1%"
set "GRADLE_VERSION=8.9"
set "GRADLE_SHA256=d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab"
if defined GRADLE_USER_HOME (set "CACHE_ROOT=%GRADLE_USER_HOME%\netcontrol-gradle-bootstrap") else (set "CACHE_ROOT=%USERPROFILE%\.gradle\netcontrol-gradle-bootstrap")
set "GRADLE_HOME=%CACHE_ROOT%\gradle-%GRADLE_VERSION%"
if exist "%GRADLE_HOME%\bin\gradle.bat" goto run
where powershell.exe >nul 2>nul || (echo PowerShell is required to bootstrap Gradle.& exit /b 2)
if not exist "%CACHE_ROOT%" mkdir "%CACHE_ROOT%"
set "TMP_DIR=%CACHE_ROOT%\.download-%RANDOM%"
mkdir "%TMP_DIR%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $zip=Join-Path '%TMP_DIR%' 'gradle-%GRADLE_VERSION%-bin.zip'; Invoke-WebRequest -Uri 'https://services.gradle.org/distributions/gradle-%GRADLE_VERSION%-bin.zip' -OutFile $zip; $actual=(Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant(); if ($actual -ne '%GRADLE_SHA256%') { throw 'Gradle distribution checksum mismatch; refusing to execute it.' }; Expand-Archive -LiteralPath $zip -DestinationPath '%TMP_DIR%' -Force"
if errorlevel 1 (rmdir /s /q "%TMP_DIR%" 2>nul & exit /b 3)
if exist "%GRADLE_HOME%" rmdir /s /q "%GRADLE_HOME%"
move "%TMP_DIR%\gradle-%GRADLE_VERSION%" "%GRADLE_HOME%" >nul
rmdir /s /q "%TMP_DIR%" 2>nul
:run
call "%GRADLE_HOME%\bin\gradle.bat" --project-dir "%APP_HOME%" %*
exit /b %ERRORLEVEL%
