package io.github.reajason.dubbo.fixture.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class BytecodeLoadingSupport {

    private BytecodeLoadingSupport() {
    }

    public static String loadBase64(String base64) {
        String normalized = normalizeBase64(base64);
        byte[] bytes = Base64.getMimeDecoder().decode(normalized);
        return loadClassBytes(bytes);
    }

    public static String loadClassBytes(byte[] bytes) {
        requireClassBytes(bytes);
        try {
            return new PayloadClassLoader(hostClassLoader()).defineAndInstantiate(bytes);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to load bytecode payload", e);
        }
    }

    private static String normalizeBase64(String base64) {
        if (base64 == null) {
            throw new IllegalArgumentException("base64 must not be null");
        }
        String trimmed = base64.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("base64 must not be blank");
        }
        return trimmed;
    }

    private static void requireClassBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("class bytes must not be empty");
        }
    }

    private static ClassLoader hostClassLoader() {
        ClassLoader classLoader = BytecodeLoadingSupport.class.getClassLoader();
        if (classLoader == null) {
            classLoader = Thread.currentThread().getContextClassLoader();
        }
        return classLoader;
    }

    public static Class<?> defineIntoHostClassLoader(String className, byte[] bytes) {
        if (className == null || className.trim().isEmpty()) {
            throw new IllegalArgumentException("class name must not be blank");
        }
        requireClassBytes(bytes);

        ClassLoader classLoader = hostClassLoader();
        Class<?> loadedClass = findLoadedClass(className, classLoader);
        if (loadedClass != null) {
            return loadedClass;
        }

        try {
            return defineClass(className, bytes, classLoader);
        } catch (LinkageError e) {
            loadedClass = findLoadedClass(className, classLoader);
            if (loadedClass != null) {
                return loadedClass;
            }
            throw e;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to define class in host class loader: " + className, e);
        }
    }

    public static void registerWithDubboClassPool(String className, byte[] bytes) {
        if (className == null || className.trim().isEmpty() || bytes == null || bytes.length == 0) {
            return;
        }

        Class<?> classPoolClass = null;
        List<Object> classPools = new ArrayList<Object>();
        try {
            classPoolClass = Class.forName("javassist.ClassPool", false, hostClassLoader());
            classPools.add(classPoolClass.getMethod("getDefault").invoke(null));
            classPools.addAll(dubboClassGeneratorPools());

            for (Object classPool : classPools) {
                if (classPoolContains(classPoolClass, classPool, className)) {
                    continue;
                }
                Method makeClass = classPoolClass.getMethod("makeClass", InputStream.class);
                makeClass.invoke(classPool, new ByteArrayInputStream(bytes));
            }
        } catch (ClassNotFoundException ignored) {
            // Javassist is not present for all clients.
        } catch (InvocationTargetException e) {
            if (classPoolClass != null && anyClassPoolContains(classPoolClass, classPools, className)) {
                return;
            }
            throw new IllegalStateException("failed to register class with Dubbo Javassist pool: " + className, e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to register class with Dubbo Javassist pool: " + className, e);
        }
    }

    private static Class<?> findLoadedClass(String className, ClassLoader classLoader) {
        try {
            return Class.forName(className, false, classLoader);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private static Class<?> defineClass(String className, byte[] bytes, ClassLoader classLoader)
            throws ReflectiveOperationException {
        Method defineClass = ClassLoader.class.getDeclaredMethod(
                "defineClass",
                String.class,
                byte[].class,
                int.class,
                int.class,
                ProtectionDomain.class
        );
        defineClass.setAccessible(true);
        try {
            return (Class<?>) defineClass.invoke(
                    classLoader,
                    className,
                    bytes,
                    0,
                    bytes.length,
                    BytecodeLoadingSupport.class.getProtectionDomain()
            );
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof LinkageError) {
                throw (LinkageError) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw e;
        }
    }

    private static List<Object> dubboClassGeneratorPools() {
        List<Object> classPools = new ArrayList<Object>();
        List<ClassLoader> classLoaders = new ArrayList<ClassLoader>();
        addClassLoader(classLoaders, hostClassLoader());
        addClassLoader(classLoaders, Thread.currentThread().getContextClassLoader());

        for (ClassLoader classLoader : classLoaders) {
            addDubboClassGeneratorPool(classPools, "com.alibaba.dubbo.common.bytecode.ClassGenerator", classLoader);
            addDubboClassGeneratorPool(classPools, "org.apache.dubbo.common.bytecode.ClassGenerator", classLoader);
        }
        return classPools;
    }

    private static void addClassLoader(List<ClassLoader> classLoaders, ClassLoader classLoader) {
        if (classLoader != null && !classLoaders.contains(classLoader)) {
            classLoaders.add(classLoader);
        }
    }

    private static void addDubboClassGeneratorPool(List<Object> classPools, String className, ClassLoader classLoader) {
        try {
            Class<?> classGeneratorClass = Class.forName(className, false, hostClassLoader());
            Method getClassPool = classGeneratorClass.getMethod("getClassPool", ClassLoader.class);
            Object classPool = getClassPool.invoke(null, classLoader);
            if (classPool != null && !classPools.contains(classPool)) {
                classPools.add(classPool);
            }
        } catch (ClassNotFoundException ignored) {
            // This runtime is using the other Dubbo namespace.
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to resolve Dubbo class pool from " + className, e);
        }
    }

    private static boolean anyClassPoolContains(Class<?> classPoolClass, List<Object> classPools, String className) {
        for (Object classPool : classPools) {
            try {
                if (classPoolContains(classPoolClass, classPool, className)) {
                    return true;
                }
            } catch (ReflectiveOperationException ignored) {
            }
        }
        return false;
    }

    private static boolean classPoolContains(Class<?> classPoolClass, Object classPool, String className)
            throws ReflectiveOperationException {
        try {
            Method getOrNull = classPoolClass.getMethod("getOrNull", String.class);
            return getOrNull.invoke(classPool, className) != null;
        } catch (NoSuchMethodException e) {
            try {
                Method get = classPoolClass.getMethod("get", String.class);
                return get.invoke(classPool, className) != null;
            } catch (InvocationTargetException invocationTargetException) {
                Throwable cause = invocationTargetException.getCause();
                if (cause != null && "javassist.NotFoundException".equals(cause.getClass().getName())) {
                    return false;
                }
                throw invocationTargetException;
            }
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause != null && "javassist.NotFoundException".equals(cause.getClass().getName())) {
                return false;
            }
            throw e;
        }
    }

    private static final class PayloadClassLoader extends ClassLoader {

        private PayloadClassLoader(ClassLoader parent) {
            super(parent);
        }

        private String defineAndInstantiate(byte[] bytes) throws ReflectiveOperationException {
            Thread thread = Thread.currentThread();
            ClassLoader original = thread.getContextClassLoader();
            thread.setContextClassLoader(this);
            try {
                Object instance = defineClass(bytes, 0, bytes.length).newInstance();
                return String.valueOf(instance);
            } finally {
                thread.setContextClassLoader(original);
            }
        }
    }
}
