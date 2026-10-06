package com.reajason.javaweb.boot.config;

import com.reajason.javaweb.boot.mcp.McpPayloadWriter;
import com.reajason.javaweb.boot.mcp.MemShellMcpTools;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MCP 默认关闭是既定的安全姿态，且必须对既有 REST 部署零影响。
 * 这组断言防止后续改动无意中把默认值翻成开启。
 *
 * @author ReaJason
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpDisabledByDefaultTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void mcpBeansAreAbsentByDefault() {
        assertTrue(context.getBeansOfType(MemShellMcpTools.class).isEmpty(),
                "MCP tools must not be registered unless spring.ai.mcp.server.enabled=true");
        assertTrue(context.getBeansOfType(McpPayloadWriter.class).isEmpty(),
                "MCP payload writer must not be registered unless explicitly enabled");
        assertTrue(context.getBeansOfType(McpAccessFilter.class).isEmpty(),
                "MCP access filter must not be registered unless explicitly enabled");
    }

    @Test
    void noMcpOutputDirectoryIsCreatedWhenDisabled() {
        assertTrue(Files.notExists(Path.of("./memshell-output")),
                "a disabled MCP server must not touch the filesystem");
    }
}
