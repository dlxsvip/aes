package com.yyl.client;

import com.yyl.client.utils.AESUtil;
import com.yyl.client.utils.StringUtil;
import sun.misc.BASE64Encoder;

import java.security.SecureRandom;

/**
 * AES 加密工具 3.0 <br>
 * Created by y0507 on 2016/9/22.
 * <p/>
 *
 */
public class TestAes {


    /**
     * 加密位数
     */
    private static int keySize = 128;
    /**
     * 加密模式
     */
    private static String model = "AES/CBC/PKCS5Padding";

    /**
     * 加密 or 解密
     */
    private static String type;

    /**
     * 盐值
     */
    private static String salt;

    /**
     * 向量
     */
    private static String iv;

    /**
     * 密钥
     */
    private static String key;

    /**
     * 加密  or 解密 内容
     */
    private static String txt;


    public static void main(String[] args) {
        //test();

        for (int i = 0; i < args.length; i++) {
            type = args[0];

            if ("-keySize".equals(args[i])) {
                keySize = Integer.parseInt(args[++i]);
            }

            if ("-m".equals(args[i])) {
                model = args[++i];
            }

            if ("-s".equals(args[i])) {
                salt = args[++i];
            }

            if ("-i".equals(args[i])) {
                iv = args[++i];
            }

            if ("-k".equals(args[i])) {
                key = args[++i];
            }

            if ("-t".equals(args[i])) {
                txt = args[++i];
            }

            //System.out.print(args[i] + ", ");
        }

        if (StringUtil.isEmpty(txt) && args.length >= 2) {
            txt = args[args.length - 1];
        }

        if (StringUtil.isEmpty(txt)) {
            return;
        }

        execute();
    }

    private static void execute() {

        // 初始化AES
        AESUtil aes = AESUtil.getInstance(keySize, model);

        String mm = "";
        if ("-e".equals(type)) {
            mm = aes.encrypt(salt, iv, key, txt);
        } else {
            mm = aes.decrypt(salt, iv, key, txt);
        }

        System.out.println(mm);
        System.out.println();
    }


    private static String getRandom(int length) {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[length];
        random.nextBytes(saltBytes);

        // 转 64
        String salt = new BASE64Encoder().encode(saltBytes);
        //System.out.println("随机数：" + salt);

        return salt;
    }

}
