package com.reajason.javaweb.memshell.spi;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;

/**
 * SPI interface for shell tool plugins.
 * Discovered via ServiceLoader; metadata provided by @ShellToolMeta annotation.
 *
 * @author ReaJason
 * @since 3.0.0
 */
public interface ShellToolProvider {

    /**
     * The complete mapping of ShellType -&gt; shell implementation class.
     */
    ToolMapping getToolMapping();

    /**
     * The ShellToolConfig subclass for this tool.
     */
    Class<? extends ShellToolConfig> getConfigClass();

    /**
     * The ShellGenerator subclass for this tool.
     */
    Class<? extends ShellGenerator> getGeneratorClass();
}
