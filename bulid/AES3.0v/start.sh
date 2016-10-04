#!/usr/bin/bash

echo -e "\033[32m=============================\033[0m"
echo -e "\033[32m 提示: 退出请按【q + 回车】      \033[0m"
echo -e "\033[32m 解密: 密文后加 -d 参数         \033[0m"
echo -e "\033[32m=============================\033[0m"



while :
do
    read -p "请输入密码 :" pwd
    if [ "$pwd" == "" ];then
        echo -e "\033[31merror:not null\033[0m"
    elif [ "$pwd" == "q" ];then
        exit 0
    else
        java -jar `dirname $0`/lib/aes.jar "$pwd"
fi
done