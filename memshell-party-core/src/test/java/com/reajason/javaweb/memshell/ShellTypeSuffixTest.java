package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 */
class ShellTypeSuffixTest {

    @Test
    void everyShellTypeHasNaturalSuffix() throws IllegalAccessException {
        for (Field field : ShellType.class.getFields()) {
            if (!Modifier.isStatic(field.getModifiers()) || field.getType() != String.class) {
                continue;
            }
            String shellType = (String) field.get(null);
            String suffix = ShellTypeSuffix.of(shellType);
            assertNotNull(suffix, field.getName());
            assertTrue(suffix.matches("[A-Z][A-Za-z0-9]*"), field.getName() + " -> " + suffix);
        }
    }

    @Test
    void removesInternalShellTypeMarkers() {
        assertEquals("Filter", ShellTypeSuffix.of(ShellType.JAKARTA_FILTER));
        assertEquals("Servlet", ShellTypeSuffix.of(ShellType.JAKARTA_SERVLET));
        assertEquals("Listener", ShellTypeSuffix.of(ShellType.JAKARTA_LISTENER));
        assertEquals("Valve", ShellTypeSuffix.of(ShellType.JAKARTA_VALVE));
        assertEquals("Valve", ShellTypeSuffix.of(ShellType.JAKARTA_PROXY_VALVE));
        assertEquals("FilterChain", ShellTypeSuffix.of(ShellType.AGENT_FILTER_CHAIN));
        assertEquals("ContextValve", ShellTypeSuffix.of(ShellType.CATALINA_AGENT_CONTEXT_VALVE));
        assertEquals("Handler", ShellTypeSuffix.of(ShellType.JETTY_AGENT_HANDLER));
        assertEquals("ServletHandler", ShellTypeSuffix.of(ShellType.UNDERTOW_AGENT_SERVLET_HANDLER));
        assertEquals("FilterManager", ShellTypeSuffix.of(ShellType.WAS_AGENT_FILTER_MANAGER));
        assertEquals("ServletContext", ShellTypeSuffix.of(ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT));
        assertEquals("Interceptor", ShellTypeSuffix.of(ShellType.SPRING_WEBMVC_INTERCEPTOR));
        assertEquals("Interceptor", ShellTypeSuffix.of(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR));
        assertEquals("Controller", ShellTypeSuffix.of(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER));
        assertEquals("Controller", ShellTypeSuffix.of(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER));
        assertEquals("Servlet", ShellTypeSuffix.of(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET));
        assertEquals("WebSocket", ShellTypeSuffix.of(ShellType.WEBSOCKET));
        assertEquals("WebSocket", ShellTypeSuffix.of(ShellType.JAKARTA_WEBSOCKET));
        assertEquals("WebSocket", ShellTypeSuffix.of(ShellType.RAW_WEBSOCKET));
        assertEquals("WebSocket", ShellTypeSuffix.of(ShellType.JAKARTA_RAW_WEBSOCKET));
        assertEquals("Service", ShellTypeSuffix.of(ShellType.DUBBO_SERVICE));
        assertEquals("Service", ShellTypeSuffix.of(ShellType.APACHE_DUBBO_SERVICE));
        assertEquals("Service", ShellTypeSuffix.of(ShellType.ALIBABA_DUBBO_SERVICE));
    }

    @Test
    void unknownShellTypeKeepsRawValue() {
        assertEquals("CustomFilter", ShellTypeSuffix.of("CustomFilter"));
    }

    @Test
    void nullShellTypeRejected() {
        assertThrows(IllegalArgumentException.class, () -> ShellTypeSuffix.of(null));
    }

    @Test
    void generatedShellClassNameUsesNaturalWords() {
        for (int i = 0; i < 200; i++) {
            String className = AbstractServer.generateShellClassName(Server.Tomcat, ShellType.JAKARTA_FILTER);
            assertTrue(className.matches(
                            "org\\.apache\\.http\\.web\\.handlers\\.[a-z][a-z0-9]*\\.[A-Z][A-Za-z0-9]*Filter"),
                    className);
            assertFalse(className.contains("Jakarta"), className);
        }
    }

    @Test
    void generatedShellClassNameUsesServerSpecificPackage() {
        String className = AbstractServer.generateShellClassName(
                Server.SpringWebMvc, ShellType.SPRING_WEBMVC_INTERCEPTOR);
        assertTrue(className.startsWith("org.springframework.boot.mvc.handlers."), className);
        assertTrue(className.endsWith("Interceptor"), className);
        assertFalse(className.contains("SpringWebMvc"), className);
    }

    @Test
    void generatedAgentClassNameHidesAgentMarker() {
        String className = AbstractServer.generateShellClassName(Server.Tomcat, ShellType.AGENT_FILTER_CHAIN);
        assertTrue(className.endsWith("FilterChain"), className);
        assertFalse(className.endsWith("AgentFilterChain"), className);
    }
}
