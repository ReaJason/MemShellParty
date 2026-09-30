package com.reajason.javaweb.boot.mcp;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2026/9/30
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MemShellMcpServerTest {

    @LocalServerPort
    private int port;

    @Test
    void shouldListToolsAndGenerateShellsOverStreamableHttp() {
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
                .builder("http://localhost:" + port)
                .endpoint("/mcp")
                .build();
        try (McpSyncClient client = McpClient.sync(transport).build()) {
            client.initialize();

            McpSchema.ListToolsResult tools = client.listTools();
            List<String> toolNames = tools.tools().stream().map(McpSchema.Tool::name).toList();
            assertTrue(toolNames.containsAll(List.of("memshell_capabilities", "generate_memshell", "generate_probe_shell")),
                    "unexpected tools: " + toolNames);

            McpSchema.CallToolResult capabilities = client.callTool(
                    new McpSchema.CallToolRequest("memshell_capabilities", Map.of()));
            assertNotEquals(Boolean.TRUE, capabilities.isError());
            assertFalse(capabilities.content().isEmpty());

            McpSchema.CallToolResult memShell = client.callTool(new McpSchema.CallToolRequest("generate_memshell",
                    Map.of("request", Map.of(
                            "shellConfig", Map.of(
                                    "server", "Tomcat",
                                    "shellTool", "Godzilla",
                                    "shellType", "Filter"),
                            "shellToolConfig", Map.of(
                                    "godzillaPass", "pass",
                                    "godzillaKey", "key"),
                            "packer", "ScriptEngine"))));
            assertNotEquals(Boolean.TRUE, memShell.isError(), () -> String.valueOf(memShell.content()));
            assertFalse(memShell.content().isEmpty());

            McpSchema.CallToolResult probeShell = client.callTool(new McpSchema.CallToolRequest("generate_probe_shell",
                    Map.of("request", Map.of(
                            "probeConfig", Map.of(
                                    "probeMethod", "ResponseBody",
                                    "probeContent", "Command",
                                    "targetJreVersion", 50),
                            "probeContentConfig", Map.of(
                                    "server", "Tomcat",
                                    "reqParamName", "cmd"),
                            "packer", "Base64"))));
            assertNotEquals(Boolean.TRUE, probeShell.isError(), () -> String.valueOf(probeShell.content()));
            assertFalse(probeShell.content().isEmpty());
        }
    }
}
