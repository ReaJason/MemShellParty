package com.reajason.javaweb.memshell.spi;

import java.lang.annotation.*;

/**
 * Metadata annotation for {@link ServerProvider} implementations.
 *
 * @author ReaJason
 * @since 3.0.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
public @interface ServerMeta {
    /**
     * Unique server identifier, e.g., "Tomcat", "SpringWebFlux".
     */
    String name();

    /**
     * Display order priority. Lower values appear first.
     * Built-in servers: 0-999; community plugins: 1000+.
     */
    int order() default 1000;
}
