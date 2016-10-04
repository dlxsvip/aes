package com.yyl.server.utils;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * <br>
 * Created by yl on 2016/9/12.
 */
public class ReadUtil {

    /**
     * 读取配置文件
     *
     * @param file 配置文件路径
     * @return map
     */
    public static Map<String, String> readConfig(File file) {
        Map<String, String> prop = new HashMap<String, String>();
        if (!file.exists()) {
            return prop;
        }

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));
            //reader = new BufferedReader(new FileReader(file));
            String line = null;
            while ((line = reader.readLine()) != null)
                if (line.contains("=")) {
                    String[] split = line.split("=");
                    if (split.length == 1)
                        prop.put(split[0], "");
                    else
                        prop.put(split[0], split[1]);
                }
        } catch (IOException e) {
        } finally {
            closeIOStream(reader);
        }

        return prop;
    }


    public static String getRealPath() {
        String path = new File("").getAbsolutePath();
        return new StringBuilder().append(path).append(File.separator).toString();
    }


    public static void closeIOStream(BufferedReader reader) {
        if (null != reader) {
            try {
                reader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


}
