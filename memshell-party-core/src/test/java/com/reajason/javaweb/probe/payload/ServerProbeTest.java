package com.reajason.javaweb.probe.payload;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 */
class ServerProbeTest {

    @Test
    void shouldDetectUnknownInPlainJvm() {
        assertEquals("Unknown", ServerProbe.exit(null));
    }

    @Test
    void shouldPrefixSpringWebMvcWhenDispatcherServletOnStack() {
        String detected = org.springframework.web.servlet.DispatcherServlet.detect();
        assertTrue(detected.startsWith("SpringWebMvc,"), "detected: " + detected);
    }

    @Test
    void shouldPrefixStruts2WhenStrutsFilterOnStack() {
        String detected = org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter.detect();
        assertEquals("Struts2,Unknown", detected);
    }

    @Test
    void shouldPrefixBothFrameworksWhenBothOnStack() {
        String detected = org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter.detectWithSpringMvc();
        assertEquals("SpringWebMvc,Struts2,Unknown", detected);
    }
}
