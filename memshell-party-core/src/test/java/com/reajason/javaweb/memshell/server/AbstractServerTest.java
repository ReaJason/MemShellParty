package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
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

    @Test
    void tongWebShellUsesCacheExemptNamespace() {
        // TongWeb 的 LoadClassCache 不缓存 com.tongweb.* 的失败结果；shell 必须落在该
        // 命名空间，否则注入器的 loadClass 探测会把类名永久缓存为找不到
        String className = AbstractServer.generateShellClassName(Server.TongWeb, ShellType.FILTER);
        assertTrue(className.startsWith("com.tongweb."), className);
    }
}
