package org.apache.dubbo.config;

import java.util.List;

/**
 * Dubbo 2.7 {@code org.apache.dubbo.config.ProviderConfig} 的生成期桩：注入器只读取
 * protocols 与 registries。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public class ProviderConfig {

    public List<ProtocolConfig> getProtocols() {
        throw new UnsupportedOperationException();
    }

    public List<RegistryConfig> getRegistries() {
        throw new UnsupportedOperationException();
    }
}
