package com.yyl.server;

import com.yyl.server.utils.AESUtil;
import sun.misc.BASE64Encoder;

import java.security.SecureRandom;

/**
 * Created by yl on 2016/9/29.
 */
public class TestServer {

    public static void main(String[] args) {

        String txt="我爱你";
        String key = "11";

        String salt = getSalt(128);
        String iv = getSalt(128);
        aes128(salt, iv, key, txt);

        //String salt = getSalt(256);
        //String iv = getSalt(256);
        //aes256(salt, iv, key, txt);
    }


    private static void aes256(String salt, String iv, String key, String txt) {
        AESUtil aes = AESUtil.getInstance(256);

        System.out.println("盐值：" + salt);
        System.out.println("向量：" + iv);
        System.out.println("密钥：" + AESUtil.getKey());

        String encrypt = aes.encrypt(salt, iv, key, txt);
        System.out.println("加密：" + encrypt);

        String decrypt = aes.decrypt(salt, iv, key, encrypt);
        System.out.println("解密：" + decrypt);
    }

    private static void aes128(String salt, String iv, String key, String txt) {
        AESUtil aes = AESUtil.getInstance(128);

        System.out.println("盐值：" + salt);
        System.out.println("向量：" + iv);
        System.out.println("密钥：" + AESUtil.getKey());

        String encrypt = aes.encrypt(salt, iv, key, txt);
        System.out.println("加密：" + encrypt);

        String decrypt = aes.decrypt(salt, iv, key, encrypt);
        System.out.println("解密：" + decrypt);


    }

    private static String getSalt(int saltLength) {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[saltLength / 8];
        random.nextBytes(saltBytes);

        // 转 64
        String salt = new BASE64Encoder().encode(saltBytes);
        //System.out.println("盐值：" + salt);


        return salt;
    }

    private static void decrypt(int keySize,String salt, String iv, String key, String txt){
        AESUtil aes = AESUtil.getInstance(keySize);

        System.out.println("keySize：" + keySize);
        System.out.println("盐值：" + salt);
        System.out.println("向量：" + iv);
        System.out.println("密钥：" + key);

        String decrypt = aes.decrypt(salt, iv, key, txt);
        System.out.println("解密：" + decrypt);
    }
}
