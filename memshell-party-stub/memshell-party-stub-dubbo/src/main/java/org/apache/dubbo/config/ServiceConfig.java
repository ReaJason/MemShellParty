package org.apache.dubbo.config;

import java.util.List;

/**
 * Dubbo 2.7 {@code org.apache.dubbo.config.ServiceConfig} 的生成期桩。真实类的方法分散在
 * ServiceConfigBase / AbstractServiceConfig / AbstractInterfaceConfig 等父类上，注入器却总以
 * 本类型接收者调用，javac 发出的 invokevirtual 主类仍是 ServiceConfig —— 桩把注入器用到的
 * 方法直接平铺在本类，生成的指令与真实类型编译结果一致。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public class ServiceConfig<T> {

    public ServiceConfig() {
    }

    public void setInterface(Class<?> interfaceClass) {
        throw new UnsupportedOperationException();
    }

    public void setRef(T ref) {
        throw new UnsupportedOperationException();
    }

    public void setPath(String path) {
        throw new UnsupportedOperationException();
    }

    public void setProxy(String proxy) {
        throw new UnsupportedOperationException();
    }

    public void setProvider(ProviderConfig provider) {
        throw new UnsupportedOperationException();
    }

    public void setVersion(String version) {
        throw new UnsupportedOperationException();
    }

    public void setApplication(ApplicationConfig application) {
        throw new UnsupportedOperationException();
    }

    public void setProtocols(List<? extends ProtocolConfig> protocols) {
        throw new UnsupportedOperationException();
    }

    public void setRegistries(List<? extends RegistryConfig> registries) {
        throw new UnsupportedOperationException();
    }

    public void export() {
        throw new UnsupportedOperationException();
    }
}
