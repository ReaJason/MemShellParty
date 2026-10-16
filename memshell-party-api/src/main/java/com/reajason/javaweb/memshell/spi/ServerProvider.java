package com.reajason.javaweb.memshell.spi;

import com.reajason.javaweb.memshell.server.AbstractServer;

/**
 * SPI interface for server support plugins.
 * Discovered via ServiceLoader; metadata provided by @ServerMeta annotation.
 *
 * @author ReaJason
 * @since 3.0.0
 */
public interface ServerProvider {

    /**
     * Create the server instance. Called once and cached by the registry.
     */
    AbstractServer createServer();
}
