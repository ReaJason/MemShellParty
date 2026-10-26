package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemShellValidatorTest {

    private final MemShellValidator validator = new MemShellValidator();

    @Test
    void needsUrlPatternMatrix() {
        assertTrue(validator.needsUrlPattern("Servlet"));
        assertTrue(validator.needsUrlPattern("JakartaServlet"));
        assertTrue(validator.needsUrlPattern("ControllerHandler"));
        assertTrue(validator.needsUrlPattern("HandlerMethod"));
        assertTrue(validator.needsUrlPattern("HandlerFunction"));
        assertTrue(validator.needsUrlPattern("WebSocket"));
        assertTrue(validator.needsUrlPattern("JakartaWebSocket"));
        // RawWebSocket 依附 Filter 注入，/* 合法，不强制具体路径
        assertFalse(validator.needsUrlPattern("RawWebSocket"));
        assertFalse(validator.needsUrlPattern("JakartaRawWebSocket"));
        assertFalse(validator.needsUrlPattern("AgentFilterChain"));
        assertFalse(validator.needsUrlPattern("Listener"));
        assertFalse(validator.needsUrlPattern("Filter"));
        assertFalse(validator.needsUrlPattern("Valve"));
    }

    @Test
    void notNeedUrlPatternMatrix() {
        assertTrue(validator.notNeedUrlPattern("Listener"));
        assertTrue(validator.notNeedUrlPattern("JakartaListener"));
        assertTrue(validator.notNeedUrlPattern("Valve"));
        assertTrue(validator.notNeedUrlPattern("Interceptor"));
        assertTrue(validator.notNeedUrlPattern("WebFilter"));
        assertTrue(validator.notNeedUrlPattern("AgentFilterManager"));
        assertTrue(validator.notNeedUrlPattern("Handler"));
        assertTrue(validator.notNeedUrlPattern("JakartaHandler"));
        assertTrue(validator.notNeedUrlPattern("Customizer"));
        assertTrue(validator.notNeedUrlPattern("Upgrade"));
        assertFalse(validator.notNeedUrlPattern("ControllerHandler"));
        assertFalse(validator.notNeedUrlPattern("Servlet"));
    }

    @Test
    void invalidUrls() {
        assertTrue(validator.isInvalidUrl(null));
        assertTrue(validator.isInvalidUrl(""));
        assertTrue(validator.isInvalidUrl("/"));
        assertTrue(validator.isInvalidUrl("/*"));
        assertTrue(validator.isInvalidUrl("abc"));
        assertFalse(validator.isInvalidUrl("/hello"));
        assertFalse(validator.isInvalidUrl("/api/cmd"));
    }

    @Test
    void happyPathIsValid() {
        MemShellFormState s = baseValidState();
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void servletRequiresSpecificUrl() {
        MemShellFormState s = baseValidState();
        s.setShellType("Servlet");
        s.setUrlPattern("/*");
        assertFalse(validator.validate(s).isValid());

        s.setUrlPattern("/hello");
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void rawWebSocketAllowsWildcardUrl() {
        MemShellFormState s = baseValidState();
        s.setShellType("RawWebSocket");
        s.setUrlPattern("/*");
        assertTrue(validator.validate(s).isValid());

        s.setShellType("JakartaRawWebSocket");
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void customRequiresShellClassBase64() {
        MemShellFormState s = baseValidState();
        s.setShellTool("Custom");
        s.setToolParam(MemShellFormState.PARAM_SHELL_CLASS_BASE64, "");
        assertFalse(validator.validate(s).isValid());

        s.setToolParam(MemShellFormState.PARAM_SHELL_CLASS_BASE64, "yJf3xK9=");
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void tongWebValveNeedsVersion() {
        MemShellFormState s = baseValidState();
        s.setServer("TongWeb");
        s.setServerVersion("Unknown");
        s.setShellType("Valve");
        assertFalse(validator.validate(s).isValid());

        s.setServerVersion("7");
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void jettyHandlerNeedsVersion() {
        MemShellFormState s = baseValidState();
        s.setServer("Jetty");
        s.setServerVersion("Unknown");
        s.setShellType("Handler");
        assertFalse(validator.validate(s).isValid());

        s.setShellType("JakartaHandler");
        assertFalse(validator.validate(s).isValid());

        s.setServerVersion("12");
        assertTrue(validator.validate(s).isValid());
    }

    @Test
    void requiredFields() {
        MemShellFormState s = baseValidState();
        s.setServer("");
        s.setShellTool("");
        s.setPackingMethod("");
        MemShellValidator.Result result = validator.validate(s);
        assertFalse(result.isValid());
        assertTrue(result.getFieldErrors().containsKey("server"));
        assertTrue(result.getFieldErrors().containsKey("shellTool"));
        // 空打包方式合法：没有 packer 的宿主直接输出 raw Base64
        assertFalse(result.getFieldErrors().containsKey("packingMethod"));

        s.setPackingMethod("NotAPacker");
        assertTrue(validator.validate(s).getFieldErrors().containsKey("packingMethod"));
    }

    private MemShellFormState baseValidState() {
        MemShellFormState s = new MemShellFormState();
        s.setServer("Tomcat");
        s.setServerVersion("Unknown");
        s.setShellTool("Godzilla");
        s.setShellType("Listener");
        s.setPackingMethod(Packers.DefaultBase64);
        return s;
    }
}
