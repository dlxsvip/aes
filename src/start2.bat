@echo off 
:: 文件编码 请用 ANSI

title AES加密
::@mode con lines=18 cols=40

::	  0 = 黑色       8 = 灰色
::    1 = 蓝色       9 = 淡蓝色
::    2 = 绿色       A = 淡绿色
::    3 = 湖蓝色     B = 淡浅绿色
::    4 = 红色       C = 淡红色
::    5 = 紫色       D = 淡紫色
::    6 = 黄色       E = 淡黄色
::    7 = 白色       F = 亮白色

:: 例:2f 第一个为背景，第二个则为前景

echo     【-e】: 加密
echo     【-d】: 解密
echo     【 q】: 退出
echo -----------------------------

:encrypt
color 02
echo.
set txt=
set /p txt="加密:"
if "%txt%" == "q"  exit
if "%txt%" == "-q" exit
if "%txt%" == "-e" goto encrypt
if "%txt%" == "-d" goto decrypt
if "%txt%" == "-r" goto random
java -jar "%~dp0lib\aes.jar" "-e" %txt%
goto encrypt


:decrypt
color 04
echo.
set pwd=
set /p pwd="解密:"
if "%pwd%" == "q"  exit
if "%pwd%" == "-q" exit
if "%pwd%" == "-e" goto encrypt
if "%pwd%" == "-d" goto decrypt
if "%pwd%" == "-r" goto random
java -jar "%~dp0lib\aes.jar" "-d" %pwd%
goto decrypt

:random
color 06
echo.
set tmp= 
set num=
set /p num="随机数长度:"
if "%num%" == "q"  exit
if "%num%" == "-q" exit
if "%num%" == "-e" goto encrypt
if "%num%" == "-d" goto decrypt
if "%num%" == "-r" goto random
echo %num%|findstr /be "[0-9]*" >nul && set tmp=%num% || echo 请输入数字
java -jar "%~dp0lib\aes.jar" "-r" %tmp%
goto random


:: call:cl
:: :cl
:: color 02
:: echo 请输入数字
:: goto random

pause
