@echo off 
:: �ļ����� ���� ANSI

color 2f


echo ��ʾ: 
echo     ��-e��: ����
echo     ��-d��: ����
echo     �� q��: �˳�
echo -----------------------------

:encrypt
echo.
set txt=
set /p txt="����:" 
if "%txt%" == "q"  exit 
if "%txt%" == "-q" exit 
if "%txt%" == "-e" goto encrypt
if "%txt%" == "-d" goto decrypt

java -jar "%~dp0lib\aes.jar" "-e" %txt%
goto encrypt
 

:decrypt
echo.
set pwd=
set /p pwd="����:"
if "%pwd%" == "q"  exit 
if "%pwd%" == "-q" exit 
if "%pwd%" == "-e" goto encrypt
if "%pwd%" == "-d" goto decrypt

java -jar "%~dp0lib\aes.jar" "-d" %pwd%
goto decrypt


pause
