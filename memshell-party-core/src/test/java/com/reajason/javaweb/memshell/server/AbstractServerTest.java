package com.reajason.javaweb.memshell.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自定义 shellType 不一定符合采样器的 PascalCase 约定，生成类名时要先规范化。
 *
 * @author ReaJason
 */
class AbstractServerTest {

    @Test
    void sanitizesCustomShellTypes() {
        assertEquals("MyFilter", AbstractServer.toClassNameSuffix("my_filter"));
        assertEquals("MyFilter", AbstractServer.toClassNameSuffix("myFilter"));
        assertEquals("MyFilter", AbstractServer.toClassNameSuffix("my filter"));
        assertEquals("Filter", AbstractServer.toClassNameSuffix("Filter"));
    }

    @Test
    void overlongSuffixFallsBackToHandler() {
        String tooLong = String.join("", java.util.Collections.nCopies(59, "A"));
        assertEquals("Handler", AbstractServer.toClassNameSuffix(tooLong));
    }

    @Test
    void generatesValidClassNameForCustomShellType() {
        String className = AbstractServer.generateShellClassName("Tomcat", "my_filter");
        assertTrue(className.matches("[a-z][a-z0-9.]*\\.[A-Z][A-Za-z0-9]*"), className);
        assertTrue(className.endsWith("MyFilter"), className);
    }
}
