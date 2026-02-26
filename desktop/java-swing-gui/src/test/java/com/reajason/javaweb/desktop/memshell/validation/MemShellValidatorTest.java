package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MemShellValidatorTest {
    private final MemShellValidator validator = new MemShellValidator();

    @Test
    void shouldRejectGenericUrlPatternWhenRequired() {
        MemShellFormState s = new MemShellFormState();
        s.setPackingMethod("Base64");
        s.setShellType("Servlet");
        s.setUrlPattern("/*");

        MemShellValidator.Result result = validator.validate(s);
        assertFalse(result.isValid());
        assertTrue(result.getFieldErrors().containsKey("urlPattern"));
    }

    @Test
    void shouldAllowNoUrlPatternForListener() {
        MemShellFormState s = new MemShellFormState();
        s.setPackingMethod("Base64");
        s.setShellType("Listener");
        s.setUrlPattern("/*");

        MemShellValidator.Result result = validator.validate(s);
        assertTrue(result.isValid());
    }

    @Test
    void shouldRequireCustomShellBase64ForCustomTool() {
        MemShellFormState s = new MemShellFormState();
        s.setPackingMethod("Base64");
        s.setShellTool("Custom");
        s.setShellClassBase64("");

        MemShellValidator.Result result = validator.validate(s);
        assertFalse(result.isValid());
        assertTrue(result.getFieldErrors().containsKey("shellClassBase64"));
    }

    @Test
    void shouldRequireJettyVersionForHandler() {
        MemShellFormState s = new MemShellFormState();
        s.setPackingMethod("Base64");
        s.setServer("Jetty");
        s.setShellType("Handler");
        s.setServerVersion("Unknown");
        s.setUrlPattern("/x");

        MemShellValidator.Result result = validator.validate(s);
        assertFalse(result.isValid());
        assertTrue(result.getFieldErrors().containsKey("serverVersion"));
    }
}
