package com.alibaba.dubbo.common;

/**
 * Dubbo 2.6 {@code com.alibaba.dubbo.common.URL} 的生成期桩：注入器只读取协议、端口和路径。
 * 真实类型是 final class，桩保持同样的类型种类。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public final class URL {

    public String getProtocol() {
        throw new UnsupportedOperationException();
    }

    public int getPort() {
        throw new UnsupportedOperationException();
    }

    public String getPath() {
        throw new UnsupportedOperationException();
    }
}
