package com.yyl.client.utils;

/**
 * <br>
 * Created by yl on 2016/9/22.
 */
public class StringUtil {
    public static boolean isEmpty(String str) {
        if (null == str || "".equals(str.trim())) {
            return true;
        }
        return false;
    }
}
