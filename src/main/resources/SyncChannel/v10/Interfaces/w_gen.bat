rem Author: Metis
cls
chcp 1251
set WSDL_FILE=SyncChannelHttp_Service.wsdl
set JAR_FILE=shep_v2.0.Sync.jar
set GEN_DIR=kz
set WSDL_DIR=wsdl

rmdir %GEN_DIR% /s/q
rmdir %WSDL_DIR% /s/q
              
"C:\Program Files\Java\jdk1.7.0_75\bin\wsimport" -p kz.inessoft.ws.shep_v20.Sync %WSDL_FILE%

mkdir %WSDL_DIR%                                       
copy *.wsdl %WSDL_DIR%

del %JAR_FILE%
"C:\Program Files\Java\jdk1.7.0_75\bin\jar" cf %JAR_FILE% kz wsdl


pause