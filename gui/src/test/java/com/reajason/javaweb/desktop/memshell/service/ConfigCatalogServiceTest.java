package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigCatalogServiceTest {

    private final ConfigCatalogService service = new ConfigCatalogService();

    @Test
    void catalogIsLoaded() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        assertFalse(catalog.getCore().isEmpty());
        assertFalse(catalog.getCustomShellTypes().isEmpty());
        assertFalse(catalog.getPackers().isEmpty());
        assertFalse(catalog.getCommandEncryptors().isEmpty());
        assertFalse(catalog.getCommandImplementationClasses().isEmpty());
    }

    @Test
    void tomcatSupportsGodzillaListener() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        Map<String, List<String>> toolMap = catalog.getCore().get("Tomcat");
        assertNotNull(toolMap);
        assertTrue(toolMap.containsKey("Godzilla"));
        assertTrue(toolMap.get("Godzilla").contains("Listener"));
    }

    @Test
    void packerTreeStructure() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        List<PackerCategory> packers = catalog.getPackers();

        PackerCategory base64 = find(packers, "Base64");
        assertNotNull(base64, "Base64 category should exist");
        assertTrue(base64.hasChildren());
        assertTrue(base64.getChildren().contains("DefaultBase64"));

        PackerCategory jar = find(packers, "Jar");
        assertNotNull(jar, "Jar category should exist");
        assertFalse(jar.hasChildren());

        PackerCategory javaDeserialize = find(packers, "JavaDeserialize");
        assertNotNull(javaDeserialize, "JavaDeserialize category should exist");
        assertTrue(javaDeserialize.hasChildren());

        PackerCategory agentJar = find(packers, "AgentJar");
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
    void commandConfigs() {
        ConfigCatalogService.ConfigCatalog catalog = service.load();
        assertEquals(Arrays.asList("RAW", "BASE64", "DOUBLE_BASE64"), catalog.getCommandEncryptors());
        assertEquals(Arrays.asList("RuntimeExec", "ForkAndExec"), catalog.getCommandImplementationClasses());
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
