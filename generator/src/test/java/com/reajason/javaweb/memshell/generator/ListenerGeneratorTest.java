package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.server.TomcatShell;
import com.reajason.javaweb.memshell.shelltool.command.CommandListener;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2025/4/27
 */
class ListenerGeneratorTest {

    @Test
    void testCommonListener() {
        Class<?> clazz = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, CommandListener.class);
        assertNotNull(clazz);
    }
}