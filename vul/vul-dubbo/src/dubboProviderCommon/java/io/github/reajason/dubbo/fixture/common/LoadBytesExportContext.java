package io.github.reajason.dubbo.fixture.common;

import java.util.List;

public final class LoadBytesExportContext {

    private static volatile Object application;
    private static volatile Object registry;
    private static volatile List<?> protocols;

    private LoadBytesExportContext() {
    }

    public static void register(Object applicationConfig, Object registryConfig, List<?> protocolConfigs) {
        application = applicationConfig;
        registry = registryConfig;
        protocols = protocolConfigs;
    }

    public static Object application() {
        return application;
    }

    public static Object registry() {
        return registry;
    }

    public static List<?> protocols() {
        return protocols;
    }
}
