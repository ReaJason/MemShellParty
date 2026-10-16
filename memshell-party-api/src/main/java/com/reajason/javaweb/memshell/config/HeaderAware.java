package com.reajason.javaweb.memshell.config;

/**
 * Capability interface for tool configs whose traffic is identified by a
 * fixed HTTP header pair. Consumed by the WebSocket bypass helper generation
 * so that core stays decoupled from concrete shell tool configs.
 *
 * @author ReaJason
 * @since 3.0.0
 */
public interface HeaderAware {
    String getHeaderName();

    String getHeaderValue();
}
