package com.alibaba.dubbo.config;

import java.util.List;

/**
 * Dubbo 2.6 {@code com.alibaba.dubbo.config.ProviderConfig} 的生成期桩：注入器只读取
 * version / application / protocols / registries。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public class ProviderConfig {

    public String getVersion() {
        throw new UnsupportedOperationException();
    }

    public ApplicationConfig getApplication() {
        throw new UnsupportedOperationException();
    }

    public List<ProtocolConfig> getProtocols() {
        throw new UnsupportedOperationException();
    }

    public List<RegistryConfig> getRegistries() {
        throw new UnsupportedOperationException();
    }
}
