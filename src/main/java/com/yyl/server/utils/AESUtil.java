package com.yyl.server.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Map;

/**
 * AES 256位 加密需要获得无政策限制权限文件
 * 主要是为了突破AES算法只能支持到128位的限制。如果未替换报 Illegal key size 错误
 * <p/>
 * 替换%JAVE_HOME%\jre\lib\security下的local_policy.jar 和 US_export_policy.jar
 * <p/>
 * 权限文件 下载
 * jdk5: http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-java-plat-419418.html#jce_policy-1.5.0-oth-JPR
 * jdk6: http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
 * jdk7: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 * jdk8: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 * Created by yl on 2016/9/22.
 */
public class AESUtil {

    /**
     * 密钥长度:
     * 128,192,256
     * 默认128
     */
    private static int KEY_SIZE = 128;

    private static int iterationCount = 1000;

    /**
     * 算法模式 AES
     */
    private static final String MODE = "AES";

    /**
     * 算法/模式/填充 :
     * <p/>
     * AES/CBC/NoPadding        不支持
     * AES/CBC/PKCS5Padding
     * AES/CBC/ISO10126Padding
     * <p/>
     * AES/CFB/NoPadding
     * AES/CFB/PKCS5Padding
     * AES/CFB/ISO10126Padding
     * <p/>
     * AES/ECB/NoPadding         不支持
     * AES/ECB/PKCS5Padding
     * <p/>
     * AES/OFB/NoPadding
     * AES/OFB/PKCS5Padding
     * AES/OFB/ISO10126Padding
     * <p/>
     * AES/PCBC/NoPadding        不支持
     * AES/PCBC/PKCS5Padding
     * AES/PCBC/ISO10126Padding
     */
    private static String PADDING = "AES/CBC/PKCS5Padding";

    /**
     * 工作模式:
     * ECB,CBC,PCBC,CTR,CTS,CFB,CFB8到128,OFB,OFB8到128
     */
    private static String WORK = "";

    /**
     * 加密解密
     */
    private static Cipher cipher;


    /**
     * 密钥配置文件
     */
    private static final String RSA_PAIR_FILENAME = "/aes_key.ini";


    /**
     * 默认密钥
     */
    private static String key = "0123456789012345";

    /**
     * 默认盐值
     */
    private static String salt = "0123456789012345";

    /**
     * 默认向量
     */
    private static String iv = "0123456789012345";

    /**
     * AES 单例
     */
    private static AESUtil INSTANCE;

    /**
     * 读取配置文件,更新默认密钥
     *
     */
    static {
        readConf();
    }

    /**
     * 获得AES 实例
     *
     * @param keySize 128/256
     * @return AES 实例
     */
    public static AESUtil getInstance(int keySize) {
        if (null == INSTANCE) {
            INSTANCE = new AESUtil(keySize);
        }

        return INSTANCE;
    }

    /**
     * 私有化构造函数
     *
     * @param keySize 128/256
     */
    private AESUtil(int keySize) {
        try {
            AESUtil.KEY_SIZE = keySize;
            AESUtil.cipher = Cipher.getInstance(PADDING);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * 加密
     *
     * @param txt 待加密的内容
     * @param key 加密密钥
     * @return 密文
     */
    public static String encrypt(String salt, String iv, String key, String txt) {
        if (StringUtil.isEmpty(salt)) {
            salt = AESUtil.salt;
        }

        if (StringUtil.isEmpty(iv)) {
            iv = AESUtil.iv;
        }

        if (StringUtil.isEmpty(key)) {
            key = AESUtil.key;
        }

        return base64Encode(encrypt2Bytes(salt, iv, key, txt));
    }

    /**
     * 解密
     *
     * @param txt 待解密的内容
     * @param key 解密密钥
     * @return 明文
     */
    public static String decrypt(String salt, String iv, String key, String txt) {
        if (StringUtil.isEmpty(salt)) {
            salt = AESUtil.salt;
        }

        if (StringUtil.isEmpty(iv)) {
            iv = AESUtil.iv;
        }

        if (StringUtil.isEmpty(key)) {
            key = AESUtil.key;
        }

        return decryptByBytes(salt, iv, key, base64Decode(txt));
    }

    private static byte[] encrypt2Bytes(String salt, String iv, String key, String txt) {
        byte[] b = null;
        try {
            initCipher(Cipher.ENCRYPT_MODE, salt, iv, key);
            b = cipher.doFinal(txt.getBytes("utf-8"));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return b;
    }


    private static String decryptByBytes(String salt, String iv, String key, byte[] bytes) {
        byte[] b = null;
        try {
            initCipher(Cipher.DECRYPT_MODE, salt, iv, key);
            b = cipher.doFinal(bytes);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return new String(b);
    }


    // byte 2 string
    private static String base64Encode(byte[] bytes) {
        return new BASE64Encoder().encode(bytes);
    }

    // string 2 byte
    private static byte[] base64Decode(String content) {
        byte[] b = null;
        try {
            b = com.yyl.server.utils.StringUtil.isEmpty(content) ? null : new BASE64Decoder().decodeBuffer(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return b;
    }

    // 读取配置文件
    private static void readConf() {
        try {
            String filePath = AESUtil.class.getResource(RSA_PAIR_FILENAME).getPath();
            File keyFile = new File(filePath);
            Map<String, String> prop = ReadUtil.readConfig(keyFile);
            if (prop.size() > 0) {
                if(prop.containsKey("key")){
                    AESUtil.key = prop.get("key");
                }
                if(prop.containsKey("salt")){
                    AESUtil.salt = prop.get("salt");
                }
                if(prop.containsKey("iv")){
                    AESUtil.iv = prop.get("iv");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initCipher(int cipherMode, String salt, String iv, String key) {
        try {
            Key keyObj = getKey(salt, key);
            byte[] ivBytes = createIV(iv);
            if ("ECB".equals(AESUtil.WORK)) {
                cipher.init(cipherMode, keyObj);
            } else {
                cipher.init(cipherMode, keyObj, new IvParameterSpec(ivBytes));
            }
        } catch (InvalidKeyException e) {
            System.out.println("请替换%JAVE_HOME%\\jre\\lib\\security下的local_policy.jar 和 US_export_policy.jar");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }


    private static Key getKey(String salt, String key) {
        Key keyObj = null;
        if (StringUtil.isEmpty(salt)) {
            keyObj = getSecretKeySpec(key);
        } else {
            keyObj = getSecretKey(salt.getBytes(), key);
        }

        return keyObj;
    }

    private static SecretKeySpec getSecretKeySpec(String key) {
        SecretKeySpec skey = null;
        try {
            // 强加密随机数生成器
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            // 使用key作为种子
            secureRandom.setSeed(key.getBytes());
            //（对称）密钥生成器  生成KEY
            KeyGenerator kgen = KeyGenerator.getInstance(MODE);
            kgen.init(KEY_SIZE, secureRandom);

            // 生成秘密（对称）密钥
            skey = new SecretKeySpec(kgen.generateKey().getEncoded(), MODE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return skey;
    }

    private static SecretKey getSecretKey(byte[] salt, String key) {
        SecretKey skey = null;
        try {
            //密钥工厂
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            //组成密钥内容的（透明）规范。
            KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, iterationCount, KEY_SIZE);
            //生成秘密（对称）密钥
            skey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), MODE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return skey;
    }


    /**
     * 初始化向量到16位
     */
    private static byte[] createIV(String pIv) throws UnsupportedEncodingException {

        byte[] bytes = pIv.getBytes("US-ASCII");

        int length = bytes.length / 16;

        if (length * 16 < bytes.length) {

            length++;

        }

        byte[] result = new byte[16];

        System.arraycopy(bytes, 0, result, 0, bytes.length > 16 ? 16 : bytes.length);

        for (int i = bytes.length; i < result.length; i++) {

            result[i] = 0x00;

        }

        return result;

    }


    public String getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[KEY_SIZE / 8];
        random.nextBytes(saltBytes);

        // 转 64
        String salt = new BASE64Encoder().encode(saltBytes);
        //System.out.println("盐值：" + salt);


        return salt;
    }

    public String getIv() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[KEY_SIZE / 8];
        random.nextBytes(ivBytes);

        // 转 64
        String iv = new BASE64Encoder().encode(ivBytes);
        //System.out.println("向量：" + iv);


        return iv;
    }

    public static String getKey() {
        return key;
    }

    public static void setKey(String key) {
        AESUtil.key = key;
    }

    public static void main(String[] args) {
        AESUtil aes = AESUtil.getInstance(256);
        String salt = aes.getSalt();
        String iv = aes.getIv();
        System.out.println("密钥：" + key);
        String txt = "我爱你";

        String encrypt = aes.encrypt(salt, iv, key, txt);
        System.out.println("加密：" + encrypt + "      " + encrypt.length());

        String decrypt = aes.decrypt(salt, iv, key, encrypt);
        System.out.println("解密：" + decrypt);

    }
}
