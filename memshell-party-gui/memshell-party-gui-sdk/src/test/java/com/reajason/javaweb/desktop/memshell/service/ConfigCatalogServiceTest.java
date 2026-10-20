package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.packer.PackerCategory;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigCatalogServiceTest {

    private final ConfigCatalogService service = new ConfigCatalogService();

    @Test
    void catalogIsLoaded() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        assertFalse(catalog.getShellTypeCatalog().getServers().isEmpty());
        assertFalse(catalog.getCustomShellTypes().isEmpty());
        assertFalse(catalog.getPackers().isEmpty());
        assertFalse(catalog.getShellToolConfigs().isEmpty());
    }

    @Test
    void tomcatSupportsGodzillaListener() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        assertTrue(catalog.getShellTypeCatalog().getShellTools("Tomcat").contains("Godzilla"));
        assertTrue(catalog.getShellTypeCatalog().getShellTypes("Tomcat", "Godzilla").contains("Listener"));
    }

    @Test
    void packerTreeStructure() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        List<PackerCategory> packers = catalog.getPackers();

        PackerCategory base64 = find(packers, "Base64");
        assertNotNull(base64, "Base64 category should exist");
        assertTrue(base64.hasChildren());
        assertTrue(base64.getChildren().contains(Packers.DefaultBase64));

        PackerCategory jar = find(packers, Packers.Jar);
        assertNotNull(jar, "Jar category should exist");
        assertFalse(jar.hasChildren());

        PackerCategory javaDeserialize = find(packers, Packers.JavaDeserialize);
        assertNotNull(javaDeserialize, "JavaDeserialize category should exist");
        assertTrue(javaDeserialize.hasChildren());

        PackerCategory agentJar = find(packers, Packers.AgentJar);
        assertNotNull(agentJar, "AgentJar category should exist");
        assertFalse(agentJar.hasChildren());
    }

    @Test
    void serverVersionOptions() {
        assertEquals(Arrays.asList("6", "7", "8"), service.getServerVersionOptions("TongWeb"));
        assertEquals(Arrays.asList("6", "7+", "12"), service.getServerVersionOptions("Jetty"));
        assertEquals(Arrays.asList("Unknown"), service.getServerVersionOptions("Jetty5"));
        assertEquals(Arrays.asList("Unknown"), service.getServerVersionOptions("Tomcat"));
    }

    @Test
    void jdkLabels() {
        assertEquals("Java 6", service.getTargetJdkLabel("50"));
        assertEquals("Java 8", service.getTargetJdkLabel("52"));
        assertEquals("Java 9", service.getTargetJdkLabel("53"));
        assertEquals("Java 11", service.getTargetJdkLabel("55"));
        assertEquals("Java 17", service.getTargetJdkLabel("61"));
        assertEquals("Java 21", service.getTargetJdkLabel("65"));
    }

    @Test
    void commandParamOptions() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        assertEquals(Arrays.asList("RAW", "BASE64", "DOUBLE_BASE64"), catalog.getParamOptions("Command", "encryptor"));
        assertEquals(Arrays.asList("RuntimeExec", "ForkAndExec"), catalog.getParamOptions("Command", "implementationClass"));
        assertTrue(catalog.getParamOptions("Command", "paramName").isEmpty(), "文本参数没有可选值");
        assertTrue(catalog.getParamOptions("Suo5", "encryptor").isEmpty(), "别的工具没有这个参数");
    }

    private PackerCategory find(List<PackerCategory> packers, String name) {
        for (PackerCategory category : packers) {
            if (category.getName().equals(name)) {
                return category;
            }
        }
        return null;
    }
}
