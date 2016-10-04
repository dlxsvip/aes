@echo off 
:: 文件编码 请用 ANSI

color 2f


echo 提示: 
echo     【-e】: 加密
echo     【-d】: 解密
echo     【 q】: 退出
echo -----------------------------

:encrypt
echo.
set txt=
set /p txt="加密:" 
if "%txt%" == "q"  exit 
if "%txt%" == "-q" exit 
if "%txt%" == "-e" goto encrypt
if "%txt%" == "-d" goto decrypt

java -jar "%~dp0lib\aes.jar" "-e" %txt%
goto encrypt
 

:decrypt
echo.
set pwd=
set /p pwd="解密:"
if "%pwd%" == "q"  exit 
if "%pwd%" == "-q" exit 
if "%pwd%" == "-e" goto encrypt
if "%pwd%" == "-d" goto decrypt

java -jar "%~dp0lib\aes.jar" "-d" %pwd%
goto decrypt


pause
