package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MemShellFormControllerTest {

    @Test
    void shouldAdjustJdkForSpringWebFluxAndResetDependentFields() {
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        controller.setServerVersion("Unknown");
        controller.setUrlPattern("/abc");

        controller.setServer("SpringWebFlux");

        assertEquals("52", controller.getState().getTargetJdkVersion());
        assertEquals("", controller.getState().getUrlPattern());
        assertNotNull(controller.getState().getShellTool());
        assertFalse(controller.getState().getShellTool().isEmpty());
    }

    @Test
    void shouldFilterAgentPackersForAgentShellType() {
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        controller.setShellType("AgentFilterChain");
        List<?> filtered = controller.getFilteredPackers();
        assertFalse(filtered.isEmpty());
        assertTrue(controller.getFilteredPackers().stream().allMatch(p -> p.getName().startsWith("Agent")));
    }

    @Test
    void shouldToggleRandomClassNameAndRestoreValues() {
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        controller.setRandomClassName(false);
        controller.setShellClassName("a.b.C");
        controller.setInjectorClassName("x.y.Z");

        controller.setRandomClassName(true);
        assertEquals("", controller.getState().getShellClassName());
        assertEquals("", controller.getState().getInjectorClassName());

        controller.setRandomClassName(false);
        assertEquals("a.b.C", controller.getState().getShellClassName());
        assertEquals("x.y.Z", controller.getState().getInjectorClassName());
    }
}
