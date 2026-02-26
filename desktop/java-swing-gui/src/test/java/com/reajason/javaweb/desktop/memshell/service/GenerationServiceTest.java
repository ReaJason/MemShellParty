package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GenerationServiceTest {
    @Test
    void shouldGenerateTomcatGodzillaListenerWithBase64Packer() {
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        controller.setServer("Tomcat");
        controller.setShellTool("Godzilla");
        controller.setShellType("Listener");
        controller.setPacker("Base64");

        GenerationService service = new GenerationService();
        DesktopMemShellGenerateResult result = service.generate(controller.getState().copy());

        assertNotNull(result);
        assertEquals("Base64", result.getPackMethod());
        assertNotNull(result.getPackResult());
        assertFalse(result.getPackResult().isEmpty());
        assertNotNull(result.getMemShellResult().getShellBytesBase64Str());
        assertNotNull(result.getMemShellResult().getInjectorBytesBase64Str());
    }
}
