package com.reajason.javaweb.vuldubbo278;

import org.apache.dubbo.common.utils.NetUtils;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;
import org.apache.dubbo.config.ServiceConfigBase;
import org.apache.dubbo.config.context.ConfigManager;
import org.apache.dubbo.rpc.model.ApplicationModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class DubboServiceInjector {
    private static final Logger logger = LoggerFactory.getLogger(DubboServiceInjector.class);

    private final Map<String, ServiceConfig<?>> dynamicServices = new ConcurrentHashMap<>();

    public String registerService(String path, String interfaceClassName, String implementationClassName) {
        String normalizedPath = normalizePath(path);
        if (normalizedPath.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }

        if (dynamicServices.containsKey(normalizedPath)) {
            String addresses = resolveServiceAddresses(normalizedPath);
            logger.info("service path [{}] already registered by injector, skipping: {}", normalizedPath, addresses);
            return addresses;
        }

        if (isPathRegisteredInFramework(normalizedPath)) {
            String addresses = resolveServiceAddresses(normalizedPath);
            logger.info("service path [{}] already registered in framework, skipping: {}", normalizedPath, addresses);
            return addresses;
        }

        Class<?> interfaceClass = loadLocalClass(interfaceClassName);
        Class<?> implementationClass = loadLocalClass(implementationClassName);
        validateServiceTypes(interfaceClass, implementationClass);

        Object serviceInstance = instantiate(implementationClass);
        ServiceConfig<Object> serviceConfig = createServiceConfig(normalizedPath, interfaceClass, serviceInstance);
        ServiceConfig<?> previous = dynamicServices.putIfAbsent(normalizedPath, serviceConfig);
        if (previous != null) {
            return resolveServiceAddresses(normalizedPath);
        }

        try {
            serviceConfig.export();
            String addresses = resolveServiceAddresses(normalizedPath);
            logger.info("registered dynamic service [{}] at {}", normalizedPath, addresses);
            return addresses;
        } catch (RuntimeException e) {
            dynamicServices.remove(normalizedPath, serviceConfig);
            throw e;
        }
    }

    private boolean isPathRegisteredInFramework(String path) {
        Collection<ServiceConfigBase> services = ApplicationModel.getConfigManager().getServices();
        return services.stream().anyMatch(s -> path.equals(s.getPath()));
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

    private Class<?> loadLocalClass(String className) {
        try {
            return Class.forName(className, true, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("class not found on local classpath: " + className, e);
        }
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
}
