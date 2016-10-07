#!/bin/bash

echo -e "\033[32m-----------------------------\033[0m"
echo -e "\033[32m【-e】: 加密                 \033[0m"
echo -e "\033[32m【-d】: 解密                 \033[0m"
echo -e "\033[32m【 q】: 退出                 \033[0m"
echo -e "\033[32m-----------------------------\033[0m"


encryptFun(){
	read -p "加密:" txt
	if [ "$txt" == "" ];then
		echo "" 
	elif [ "$txt" == "q" ];then
		exit 0
	elif [ "$txt" == "-e" ];then
		echo "" 
	elif [ "$txt" == "-d" ];then
		dncryptFun 
	else
		java -jar `dirname $0`/lib/aes.jar "-e" "$txt"
	fi
	encryptFun
}



dncryptFun(){
	read -p "解密:" txt
	if [ "$txt" == "" ];then
		echo "" 
	elif [ "$txt" == "q" ];then
		exit 0
	elif [ "$txt" == "-e" ];then
		encryptFun
	elif [ "$txt" == "-d" ];then
		echo "" 
	else
		java -jar `dirname $0`/lib/aes.jar "-d" "$txt"
	fi
	dncryptFun
}


case "$1" in
	-e)
		encryptFun ;;
	-d)
		dncryptFun ;;
	 *)
		encryptFun ;;
esac
