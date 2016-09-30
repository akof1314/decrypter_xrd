@echo off
set exevar="decrypter_xrd.exe"

for /f "usebackq tokens=*" %%d in (`dir /s /b *.upk`) do (
    %exevar% "%%d"
)