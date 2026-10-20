package org.apache.dubbo.config;

/**
 * Dubbo 2.7 {@code org.apache.dubbo.config.RegistryConfig} 的生成期桩：注入器用
 * {@code new RegistryConfig("N/A")} 作为无注册中心时的占位，并用 {@code isValid()} 过滤配置。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public class RegistryConfig {

    public RegistryConfig(String address) {
    }

    public boolean isValid() {
        throw new UnsupportedOperationException();
    }
}
