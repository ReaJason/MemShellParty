package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.ShellTool;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemShellFormControllerTest {

    private MemShellFormController newController() {
        return new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
    }

    @Test
    void initialDefaultsAreReconciled() {
        MemShellFormController c = newController();
        MemShellFormState s = c.getState();
        assertEquals("Tomcat", s.getServer());
        assertEquals("Godzilla", s.getShellTool());
        assertNotNull(s.getShellType());
        assertFalse(s.getPackingMethod().isEmpty());
        assertTrue(c.getShellTypesForCurrentTool().contains(s.getShellType()));
    }

    @Test
    void customAlwaysAppendedToTools() {
        MemShellFormController c = newController();
        List<String> tools = c.getShellTools();
        assertTrue(tools.contains(ShellTool.Custom));
        assertEquals(ShellTool.Custom, tools.get(tools.size() - 1));
    }

    @Test
    void customShellTypesComeFromInjectorMapping() {
        MemShellFormController c = newController();
        c.setShellTool(ShellTool.Custom);
        List<String> customTypes = c.getShellTypesForCurrentTool();
        List<String> mappingTypes = c.getCatalog().getCustomShellTypes().get("Tomcat");
        assertFalse(customTypes.isEmpty());
        assertEquals(mappingTypes.size(), customTypes.size());
    }

    @Test
    void jdkRaisedForWebFluxXxlJobDubbo() {
        MemShellFormController c = newController();
        c.setServer("SpringWebFlux");
        assertEquals("52", c.getState().getTargetJdkVersion());
        assertFalse(c.getState().isByPassJavaModule());

        c.setServer("XXLJOB");
        assertEquals("52", c.getState().getTargetJdkVersion());

        c.setServer("Dubbo");
        assertEquals("52", c.getState().getTargetJdkVersion());

        c.setServer("Tomcat");
        assertEquals("50", c.getState().getTargetJdkVersion());
    }

    @Test
    void targetJdkTogglesByPassJavaModule() {
        MemShellFormController c = newController();
        c.setTargetJdkVersion("53");
        assertTrue(c.getState().isByPassJavaModule());
        c.setTargetJdkVersion("61");
        assertTrue(c.getState().isByPassJavaModule());
        c.setTargetJdkVersion("52");
        assertFalse(c.getState().isByPassJavaModule());
        c.setTargetJdkVersion("50");
        assertFalse(c.getState().isByPassJavaModule());
    }

    @Test
    void serverChangeResetsUrlPatternAndVersion() {
        MemShellFormController c = newController();
        c.getState().setUrlPattern("/hello");
        c.getState().setServerVersion("9");
        c.setServer("Undertow");
        assertEquals(MemShellFormState.DEFAULT_URL_PATTERN, c.getState().getUrlPattern());
        assertEquals("Unknown", c.getState().getServerVersion());
    }

    @Test
    void shellTypeAndToolChangeResetUrlPatternToDefault() {
        MemShellFormController c = newController();
        c.getState().setUrlPattern("/hello");
        c.setShellType(c.getShellTypesForCurrentTool().get(0));
        assertEquals(MemShellFormState.DEFAULT_URL_PATTERN, c.getState().getUrlPattern());

        c.getState().setUrlPattern("/hello");
        c.setShellTool(ShellTool.Behinder);
        assertEquals(MemShellFormState.DEFAULT_URL_PATTERN, c.getState().getUrlPattern());
    }

    @Test
    void unsupportedToolFallsBack() {
        MemShellFormController c = newController();
        c.setServer("Struts2");
        MemShellFormState s = c.getState();
        List<String> tools = c.getCatalog().getCore().get("Struts2").keySet()
                .stream().collect(java.util.stream.Collectors.toList());
        assertTrue(tools.contains(s.getShellTool()));
    }

    @Test
    void shellToolChangeResetsToolFields() {
        MemShellFormController c = newController();
        // web 语义：切入目标工具时重置该工具字段并设默认 headerName
        c.setShellTool("Godzilla");
        c.getState().setGodzillaPass("pass1");
        c.getState().setGodzillaKey("key1");
        c.getState().setHeaderName("X-Custom");

        c.setShellTool("Behinder");
        MemShellFormState s = c.getState();
        assertEquals("", s.getBehinderPass());
        assertEquals("User-Agent", s.getHeaderName());
        assertEquals("", s.getHeaderValue());

        // 切回 Godzilla 时其字段被重置
        c.setShellTool("Godzilla");
        assertEquals("", c.getState().getGodzillaPass());
        assertEquals("", c.getState().getGodzillaKey());

        c.setShellTool("NeoreGeorg");
        assertEquals("Referer", c.getState().getHeaderName());

        c.getState().setShellClassBase64("abc");
        c.setShellTool("Custom");
        c.getState().setShellClassBase64("abc");
        c.setShellTool("Custom");
        assertEquals("", c.getState().getShellClassBase64());
    }

    @Test
    void packerFilterAgentOnlyForAgentShellType() {
        MemShellFormController c = newController();
        // 经 setShellType 触发 packer 重协调（Agent 类型走 Agent* 分类）
        c.setShellType("AgentFilterChain");
        List<PackerCategory> filtered = c.getFilteredPackers();
        assertFalse(filtered.isEmpty());
        for (PackerCategory category : filtered) {
            assertTrue(category.getName().startsWith("Agent"), "non-Agent leaked: " + category.getName());
        }
        assertTrue(c.getState().getPackingMethod().startsWith("Agent"));
    }

    @Test
    void packerFilterExcludesAgentAndXxlByDefault() {
        MemShellFormController c = newController();
        List<PackerCategory> filtered = c.getFilteredPackers();
        assertFalse(filtered.isEmpty());
        for (PackerCategory category : filtered) {
            String name = category.getName();
            assertFalse(name.startsWith("Agent"), "Agent leaked: " + name);
            assertFalse(name.toLowerCase().startsWith("xxl"), "xxl leaked: " + name);
        }
    }

    @Test
    void packerFilterXxlServerKeepsXxlButNotAgent() {
        MemShellFormController c = newController();
        c.setServer("XXLJOB");
        List<PackerCategory> filtered = c.getFilteredPackers();
        boolean hasXxl = false;
        for (PackerCategory category : filtered) {
            assertFalse(category.getName().startsWith("Agent"));
            if (category.getName().toLowerCase().startsWith("xxl")) {
                hasXxl = true;
            }
        }
        assertTrue(hasXxl, "XxlJob category should be kept for XXL server");
    }

    @Test
    void commandVisibilityMatrix() {
        MemShellFormController c = newController();
        c.setShellTool("Command");
        MemShellFormState s = c.getState();
        c.setShellType("Servlet");
        assertTrue(c.isCommandParamVisible());
        assertFalse(c.isCommandHeaderVisible());

        c.setShellType("WebSocket");
        assertFalse(c.isCommandParamVisible());

        c.setServer("Dubbo");
        assertFalse(c.isCommandParamVisible());

        c.setServer("Tomcat");
        c.setShellTool("Command");
        c.setShellType("BypassNginxWebSocket");
        assertTrue(c.isCommandHeaderVisible());
        assertTrue(c.isProxyHeaderVisible());
        c.setShellType("BypassNginxJakartaWebSocket");
        assertTrue(c.isCommandHeaderVisible());
        c.setShellType("Listener");
        assertFalse(c.isCommandHeaderVisible());
    }
}
