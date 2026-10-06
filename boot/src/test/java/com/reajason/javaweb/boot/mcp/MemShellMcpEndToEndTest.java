package com.reajason.javaweb.boot.mcp;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapperSupplier;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端验证：真实启动 Spring 上下文，通过 MCP Streamable HTTP 协议调用工具。
 * <p>
 * 这一层是必需的而非锦上添花——工具的参数名由反射生成 JSON Schema，
 * 缺少 {@code -parameters} 编译选项时会静默退化为 {@code arg0/arg1}，
 * 单测与编译都无法发现。
 *
 * @author ReaJason
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MemShellMcpEndToEndTest {

    /** 用 SDK 自身的 mapper，使断言所依据的编码与真实传输层一致。 */
    private static final McpJsonMapper JSON = new JacksonMcpJsonMapperSupplier().get();
    private static final Path OUTPUT_DIR = createOutputDir();

    @DynamicPropertySource
    static void mcpProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.ai.mcp.server.enabled", () -> "true");
        registry.add("memshell.mcp.output-dir", OUTPUT_DIR::toString);
    }

    @LocalServerPort
    private int port;

    private McpSyncClient client;

    @BeforeEach
    void connect() {
        client = McpClient.sync(HttpClientStreamableHttpTransport
                        .builder("http://localhost:" + port)
                        .endpoint("/mcp")
                        .build())
                .requestTimeout(Duration.ofSeconds(60))
                .build();
        client.initialize();
    }

    @AfterEach
    void disconnect() {
        if (client != null) {
            client.closeGracefully();
        }
    }

    @Test
    void exposesExactlyTheDesignedTools() {
        List<String> names = client.listTools().tools().stream()
                .map(McpSchema.Tool::name)
                .sorted()
                .toList();

        assertEquals(List.of("generate_memshell", "generate_probe", "list_support_matrix", "parse_class_name"),
                names);
    }

    @Test
    void toolParameterNamesAreRealAndNotArgIndexes() {
        Map<String, Object> properties = propertiesOf(tool("generate_memshell"));

        assertTrue(properties.containsKey("server"), "schema was " + properties.keySet());
        assertTrue(properties.containsKey("shellTool"), "schema was " + properties.keySet());
        assertTrue(properties.containsKey("shellType"), "schema was " + properties.keySet());
        assertTrue(properties.containsKey("output"), "schema was " + properties.keySet());
        assertFalse(properties.containsKey("arg0"), "parameters degraded to arg indexes: " + properties.keySet());
    }

    @Test
    void requiredParametersAreMarkedRequired() {
        McpSchema.Tool generate = tool("generate_memshell");

        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) generate.inputSchema().get("required");

        assertNotNull(required, "inputSchema has no required list");
        assertTrue(required.containsAll(List.of("server", "shellTool", "shellType")), "was " + required);
    }

    @Test
    void listSupportMatrixReturnsCapabilityMatrix() {
        Map<String, Object> payload = call("list_support_matrix", Map.of());

        @SuppressWarnings("unchecked")
        Map<String, Object> servers = (Map<String, Object>) payload.get("servers");
        assertNotNull(servers);
        assertTrue(servers.containsKey("Tomcat"), "Tomcat missing from " + servers.keySet());
        assertInstanceOf(List.class, payload.get("packers"));

        @SuppressWarnings("unchecked")
        List<String> probeMethods = (List<String>) payload.get("probeMethods");
        assertTrue(probeMethods.containsAll(List.of("DNSLog", "Sleep", "ResponseBody")), "was " + probeMethods);

        // probeContent 取值按 probeMethod 分叉，必须能查到，否则调用方只能靠试错
        @SuppressWarnings("unchecked")
        Map<String, List<String>> byMethod = (Map<String, List<String>>) payload.get("probeContentsByMethod");
        assertNotNull(byMethod, "probeContentsByMethod missing; callers cannot discover valid values");
        assertEquals(List.of("Server", "JDK"), byMethod.get("DNSLog"));
        assertEquals(List.of("Server"), byMethod.get("Sleep"));
        assertTrue(byMethod.get("ResponseBody").containsAll(List.of("Command", "Bytecode")));
    }

    @Test
    void metadataOutputWritesFilesAndDoesNotInline() {
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "pass", "pass",
                "key", "key"));

        assertEquals("memshell", payload.get("kind"));
        assertNotNull(payload.get("shellClassName"));
        assertNotNull(payload.get("injectorClassName"));
        assertNull(payload.get("content"), "metadata output must not inline the payload");
        assertNull(payload.get("contents"), "metadata output must not inline the payload");

        List<Map<String, Object>> files = filesOf(payload);
        assertFalse(files.isEmpty(), "expected at least one payload file");
        assertAllPayloadFilesExist(files);
    }

    @Test
    void singlePackerWritesExactlyOneFile() {
        // BigInteger 是单打包器（不实现 AggregatePacker），用于钉住非聚合路径
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "packer", "BigInteger"));

        assertEquals(1, filesOf(payload).size());
    }

    @Test
    void aggregatePackerWritesOneFilePerOutput() {
        // 默认打包器 Base64 实现 AggregatePacker，会展开成多个子打包器结果
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter"));

        List<Map<String, Object>> files = filesOf(payload);
        assertTrue(files.size() > 1, "expected multiple aggregate outputs but got " + files.size());
        assertAllPayloadFilesExist(files);
    }

    @Test
    void base64OutputInlinesSinglePackerContent() {
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "packer", "BigInteger",
                "output", "base64"));

        String content = (String) payload.get("content");
        assertNotNull(content, "base64 output must inline the payload");
        assertFalse(content.isBlank());
        assertTrue(filesOf(payload).isEmpty(), "base64-only output should not write files");
    }

    @Test
    void base64OutputInlinesEveryAggregateEntry() {
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "output", "base64"));

        @SuppressWarnings("unchecked")
        Map<String, String> contents = (Map<String, String>) payload.get("contents");
        assertNotNull(contents, "aggregate base64 output must inline all entries");
        assertFalse(contents.isEmpty());
        assertTrue(contents.values().stream().noneMatch(String::isBlank),
                "every aggregated payload should be non-blank");
        assertTrue(filesOf(payload).isEmpty(), "base64-only output should not write files");
    }

    @Test
    void shellToolConfigSecretsAreNeverEchoedBack() {
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "pass", "sup3r-s3cret-pass",
                "key", "sup3r-s3cret-key"));

        String serialized = serialize(payload);

        assertFalse(serialized.contains("sup3r-s3cret-pass"), "password leaked into MCP response");
        assertFalse(serialized.contains("sup3r-s3cret-key"), "key leaked into MCP response");
    }

    @Test
    void unknownPackerFallsBackAndWarnsInsteadOfFailing() {
        Map<String, Object> payload = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Godzilla",
                "shellType", "Filter",
                "packer", "NoSuchPacker"));

        assertEquals("Base64", payload.get("packer"));

        @SuppressWarnings("unchecked")
        List<String> warnings = (List<String>) payload.get("warnings");
        assertFalse(warnings.isEmpty(), "expected a warning about the unknown packer");
    }

    @Test
    void unsupportedServerSurfacesAnActionableError() {
        Map<String, Object> result = rawCall("generate_memshell", Map.of(
                "server", "NotARealServer",
                "shellTool", "Godzilla",
                "shellType", "Filter"));

        assertTrue(Boolean.TRUE.equals(result.get("isError")), "expected an error result but got " + result);
        assertTrue(serialize(result).contains("list_support_matrix"),
                "error should point the caller at list_support_matrix: " + result);
    }

    @Test
    void generateProbeDnsLogProducesPayload() {
        Map<String, Object> payload = call("generate_probe", Map.of(
                "probeMethod", "DNSLog",
                "host", "example.dnslog.invalid"));

        assertEquals("probe", payload.get("kind"));
        assertNotNull(payload.get("shellClassName"));
        assertNull(payload.get("injectorClassName"), "probes have no injector class");
        assertAllPayloadFilesExist(filesOf(payload));
    }

    @Test
    void probeContentDefaultsToTheServerDetectionSupportedByThatMethod() {
        // DNSLog 不支持 Bytecode，默认值必须跟着 probeMethod 走，否则一调用就报错
        Map<String, Object> payload = call("generate_probe", Map.of(
                "probeMethod", "DNSLog",
                "host", "example.dnslog.invalid"));

        assertFalse(filesOf(payload).isEmpty());
    }

    @Test
    void unsupportedProbeContentCombinationSurfacesGeneratorError() {
        Map<String, Object> result = rawCall("generate_probe", Map.of(
                "probeMethod", "DNSLog",
                "host", "example.dnslog.invalid",
                "probeContent", "Command"));

        assertTrue(Boolean.TRUE.equals(result.get("isError")), "expected an error result but got " + result);
    }

    @Test
    void invalidProbeMethodSurfacesAnActionableError() {
        Map<String, Object> result = rawCall("generate_probe", Map.of("probeMethod", "Telepathy"));

        assertTrue(Boolean.TRUE.equals(result.get("isError")), "expected an error result but got " + result);
        assertTrue(serialize(result).contains("list_support_matrix"),
                "error should point the caller at list_support_matrix: " + result);
    }

    @Test
    void parseClassNameReadsTheFullyQualifiedNameFromClassBytes() {
        Map<String, Object> payload = call("parse_class_name", Map.of(
                "shellClassBase64", base64Of("MemShellMcpEndToEndTest.class")));

        assertEquals(MemShellMcpEndToEndTest.class.getName(), payload.get("className"));
    }

    @Test
    void parseClassNameRejectsNonBase64Input() {
        Map<String, Object> result = rawCall("parse_class_name", Map.of(
                "shellClassBase64", "this is definitely not base64!!!"));

        assertTrue(Boolean.TRUE.equals(result.get("isError")), "expected an error result but got " + result);
    }

    @Test
    void parseClassNameRejectsBase64ThatIsNotAClassFile() {
        String notAClass = Base64.getEncoder().encodeToString("just some text".getBytes(StandardCharsets.UTF_8));

        Map<String, Object> result = rawCall("parse_class_name", Map.of("shellClassBase64", notAClass));

        assertTrue(Boolean.TRUE.equals(result.get("isError")), "expected an error result but got " + result);
    }

    /**
     * Custom 工作流的闭环：只有字节码时，先解析类名再带着它去生成。
     * 少了 parse_class_name 这一步，Custom 在 MCP 上就是断的。
     */
    @Test
    void customShellWorkflowParsesTheNameThenGenerates() {
        String customClassBase64 = base64Of(
                "/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaFilter.class");

        Map<String, Object> parsed = call("parse_class_name", Map.of("shellClassBase64", customClassBase64));
        String className = (String) parsed.get("className");
        assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter", className);

        Map<String, Object> generated = call("generate_memshell", Map.of(
                "server", "Tomcat",
                "shellTool", "Custom",
                "shellType", "Filter",
                "shellClassBase64", customClassBase64,
                "shellClassName", className));

        assertEquals("memshell", generated.get("kind"));
        assertFalse(filesOf(generated).isEmpty());
    }

    /**
     * staticInitialize 曾从 generate_memshell 的参数表里漏掉——用户选了它会被静默忽略。
     * 断言两次生成的产物不同，才能证明这个参数真的接到了注入器上。
     */
    @Test
    void staticInitializeActuallyChangesTheGeneratedPayload() {
        Map<String, Object> without = call("generate_memshell", Map.of(
                "server", "Tomcat", "shellTool", "Godzilla", "shellType", "Filter",
                "packer", "BigInteger"));
        Map<String, Object> with = call("generate_memshell", Map.of(
                "server", "Tomcat", "shellTool", "Godzilla", "shellType", "Filter",
                "packer", "BigInteger", "staticInitialize", true));

        String hashWithout = (String) filesOf(without).get(0).get("sha256");
        String hashWith = (String) filesOf(with).get(0).get("sha256");

        assertNotEquals(hashWithout, hashWith,
                "staticInitialize was accepted but had no effect on the payload");
    }

    private McpSchema.Tool tool(String name) {
        return client.listTools().tools().stream()
                .filter(tool -> name.equals(tool.name()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("tool not exposed: " + name));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> propertiesOf(McpSchema.Tool tool) {
        return (Map<String, Object>) tool.inputSchema().get("properties");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> filesOf(Map<String, Object> payload) {
        return (List<Map<String, Object>>) payload.get("files");
    }

    private static void assertAllPayloadFilesExist(List<Map<String, Object>> files) {
        for (Map<String, Object> file : files) {
            Path written = Path.of((String) file.get("path"));
            assertTrue(written.startsWith(OUTPUT_DIR), "file escaped the output dir: " + written);
            assertTrue(Files.exists(written), "payload file was not written: " + written);
        }
    }

    /**
     * 调用工具并断言成功，返回拍平后的结构化内容。
     */
    private Map<String, Object> call(String name, Map<String, Object> arguments) {
        Map<String, Object> result = rawCall(name, arguments);
        assertFalse(Boolean.TRUE.equals(result.get("isError")), "tool reported error: " + result);
        result.remove("isError");
        result.remove("raw");
        return result;
    }

    /**
     * 调用工具并把协议层结果拍平成可直接断言的 Map，保留 {@code isError} 标记。
     */
    private Map<String, Object> rawCall(String name, Map<String, Object> arguments) {
        McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(name, arguments));
        Map<String, Object> flattened = new HashMap<>();
        flattened.put("isError", result.isError());
        flattened.put("raw", serialize(result));
        if (result.structuredContent() != null) {
            flattened.putAll(JSON.convertValue(result.structuredContent(), Map.class));
        } else {
            // 错误结果的内容是纯文本异常消息，不是 JSON，直接原样保留
            for (McpSchema.Content content : result.content()) {
                if (content instanceof McpSchema.TextContent text) {
                    String body = text.text();
                    if (body != null && body.stripLeading().startsWith("{")) {
                        try {
                            flattened.putAll(JSON.readValue(body, Map.class));
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    } else {
                        flattened.put("message", body);
                    }
                    break;
                }
            }
        }
        return flattened;
    }

    private static String serialize(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * 读取类路径上的真实 .class 字节并转成 Base64，用于驱动 parse_class_name。
     * 用真实字节而非硬编码字面量，避免测试数据与编译产物脱节。
     */
    private static String base64Of(String resourcePath) {
        try (InputStream in = MemShellMcpEndToEndTest.class.getResourceAsStream(resourcePath)) {
            assertNotNull(in, "classpath resource missing: " + resourcePath);
            return Base64.getEncoder().encodeToString(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path createOutputDir() {
        try {
            return Files.createTempDirectory("memshell-mcp-e2e");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
