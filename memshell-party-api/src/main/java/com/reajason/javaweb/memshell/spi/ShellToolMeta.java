package com.reajason.javaweb.memshell.spi;

import java.lang.annotation.*;

/**
 * Metadata annotation for {@link ShellToolProvider} implementations.
 *
 * @author ReaJason
 * @since 3.0.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
public @interface ShellToolMeta {
    /**
     * Unique tool identifier, e.g., "Godzilla", "Command".
     */
    String name();

    /**
     * Display order priority. Lower values appear first — this is the order the desktop
     * GUI's tool dropdown shows.
     * <p>
     * Built-in tools use 10-90. A downstream distribution bundling its own tool alongside
     * the built-ins may use 1-9 to sit ahead of them (e.g. a self-branded client that wants
     * its own tool preselected); community plugins should use 1000+.
     */
    int order() default 1000;
}
