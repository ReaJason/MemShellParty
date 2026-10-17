package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/13
 */

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ConfigControllerIntegrationTest {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE = new ParameterizedTypeReference<>() {
    };

    private static final ParameterizedTypeReference<List<String>> STRING_LIST_TYPE = new ParameterizedTypeReference<>() {
    };

    private static final ParameterizedTypeReference<List<Map<String, Object>>> PACKER_TREE_TYPE = new ParameterizedTypeReference<>() {
    };

    private static final ParameterizedTypeReference<List<Map<String, Object>>> NODE_LIST_TYPE = new ParameterizedTypeReference<>() {
    };

    @LocalServerPort
    private int port;

    private RestClient restClient;

    @BeforeEach
    void setUp() {
        restClient = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    public void testConfigEndpoint() {
        ResponseEntity<Map<String, Object>> response = restClient.get()
                .uri("/api/config")
                .retrieve()
                .toEntity(MAP_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(MemShellRegistry.getInstance().getSupportedServers(), List.copyOf(response.getBody().keySet()));
    }

    @Test
    public void testConfigPackersTreeEndpoint() {
        ResponseEntity<List<Map<String, Object>>> response = restClient.get()
                .uri("/api/config/packers/tree")
                .retrieve()
                .toEntity(PACKER_TREE_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());

        Map<String, Object> base64 = response.getBody().stream()
                .filter(node -> "Base64".equals(node.get("name")))
                .findFirst()
                .orElseThrow();
        // 前端 PackerOption 只认 name/children，多序列化出的字段会破坏契约
        assertEquals(Set.of("name", "children"), base64.keySet());
        assertTrue(((List<?>) base64.get("children")).contains("DefaultBase64"));
    }

    @Test
    public void testConfigProbeResponseServersEndpoint() {
        ResponseEntity<List<String>> response = restClient.get()
                .uri("/api/config/probe/response/servers")
                .retrieve()
                .toEntity(STRING_LIST_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ResponseGenerator.getSupportedServers(), response.getBody());
    }

    /**
     * 工具参数目录是 web / 桌面端的表单契约：工具顺序、参数顺序、分组与枚举可选值都必须稳定，
     * 多序列化出来的字段会破坏前端解析。
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testShellToolConfigsEndpoint() {
        ResponseEntity<List<Map<String, Object>>> response = restClient.get()
                .uri("/api/config/shelltool/configs")
                .retrieve()
                .toEntity(NODE_LIST_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(MemShellRegistry.getInstance().getSupportedTools(),
                response.getBody().stream().map(node -> node.get("tool")).toList());

        Map<String, Object> command = response.getBody().stream()
                .filter(node -> "Command".equals(node.get("tool")))
                .findFirst()
                .orElseThrow();
        assertEquals(Set.of("tool", "params"), command.keySet());

        List<Map<String, Object>> params = (List<Map<String, Object>>) command.get("params");
        assertEquals(List.of("paramName", "headerName", "headerValue", "encryptor", "implementationClass", "template"),
                params.stream().map(param -> param.get("name")).toList());
        assertEquals(Set.of("name", "type", "options", "group", "label", "placeholder"), params.get(0).keySet());
        // 内置工具的参数名/提示登记在各自界面里，注解上留空；插件工具靠这两个字段显示中文名与语义提示
        assertEquals("", params.get(0).get("label"));
        assertEquals("", params.get(0).get("placeholder"));

        Map<String, Object> encryptor = params.stream()
                .filter(param -> "encryptor".equals(param.get("name")))
                .findFirst()
                .orElseThrow();
        assertEquals("enum", encryptor.get("type"));
        assertEquals("ADVANCED", encryptor.get("group"));
        assertEquals(List.of("RAW", "BASE64", "DOUBLE_BASE64"), encryptor.get("options"));

        assertEquals("BASIC", params.get(0).get("group"));
        assertEquals(List.of(), params.get(0).get("options"));
    }
}
