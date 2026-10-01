package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.ProbeShellValidator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProbeShellFormControllerTest {

    private ProbeShellFormController newController() {
        return new ProbeShellFormController(new ConfigCatalogService(), new ProbeShellValidator());
    }

    @Test
    void initialDefaultsAreReconciled() {
        ProbeShellFormController c = newController();
        ProbeShellFormState s = c.getState();
        assertEquals("ResponseBody", s.getProbeMethod());
        assertEquals("Command", s.getProbeContent());
        assertFalse(s.getPackingMethod().isEmpty());
        assertTrue(c.getProbeContents().contains(s.getProbeContent()));
        assertTrue(c.validate().isValid());
    }

    @Test
    void methodChangeResetsContentToFirstAllowed() {
        ProbeShellFormController c = newController();
        c.setProbeMethod("DNSLog");
        assertEquals("JDK", c.getState().getProbeContent());
        c.setProbeMethod("Sleep");
        assertEquals("Server", c.getState().getProbeContent());
    }

    @Test
    void methodChangeResetsSleepDefaults() {
        ProbeShellFormController c = newController();
        c.setProbeMethod("Sleep");
        c.setSleepServer("Jetty");
        c.setSeconds("30");
        c.setProbeMethod("ResponseBody");
        assertEquals("Tomcat", c.getState().getSleepServer());
        assertEquals("5", c.getState().getSeconds());
    }

    @Test
    void dnsLogRequiresHost() {
        ProbeShellFormController c = newController();
        c.setProbeMethod("DNSLog");
        c.setHost("");
        ProbeShellValidator.Result invalid = c.validate();
        assertFalse(invalid.isValid());
        assertNotNull(invalid.getFieldErrors().get("host"));

        c.setHost("xxx.dnslog.cn");
        assertTrue(c.validate().isValid());
    }

    @Test
    void sleepSecondsMustBePositiveInteger() {
        ProbeShellFormController c = newController();
        c.setProbeMethod("Sleep");

        c.setSeconds("0");
        assertFalse(c.validate().isValid());
        c.setSeconds("abc");
        assertFalse(c.validate().isValid());
        c.setSeconds("3");
        assertTrue(c.validate().isValid());
    }

    @Test
    void packersExcludeAgentJarAndXxl() {
        ProbeShellFormController c = newController();
        List<PackerCategory> packers = c.getFilteredPackers();
        assertFalse(packers.isEmpty());
        for (PackerCategory category : packers) {
            String name = category.getName();
            String lower = name.toLowerCase(Locale.ROOT);
            assertFalse(name.startsWith("Agent"), name);
            assertFalse(lower.startsWith("xxl"), name);
            assertFalse(lower.endsWith("jar"), name);
        }
        // 探测马目录无状态过滤，选择恒有效
        assertNotNull(c.findCategoryOf(c.getState().getPackingMethod()));
    }

    @Test
    void responseBodyServersComeFromGenerator() {
        ProbeShellFormController c = newController();
        List<String> servers = c.getResponseBodyServers();
        assertFalse(servers.isEmpty());
        assertTrue(servers.contains("Tomcat"));
    }

    @Test
    void jdkChangeAutoEnablesBypass() {
        ProbeShellFormController c = newController();
        c.setTargetJdkVersion("61");
        assertTrue(c.getState().isByPassJavaModule());
        c.setTargetJdkVersion("50");
        assertFalse(c.getState().isByPassJavaModule());
    }

    @Test
    void snapshotCopyIsIndependent() {
        ProbeShellFormController c = newController();
        ProbeShellFormState snapshot = c.getState().copy();
        c.setHost("changed.dnslog.cn");
        assertFalse(snapshot.getHost().equals(c.getState().getHost()));
    }
}
