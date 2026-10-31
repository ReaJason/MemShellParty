package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ObfuscationScope;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.PackerSupport;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2025/9/16
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MemShellGeneratorControllerTest {

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
    void generateShell() {
        MemShellGenerateRequest request = new MemShellGenerateRequest();
        request.setShellConfig(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Godzilla)
                .shrink(true)
                .debug(true)
                .lambdaSuffix(true)
                .serverVersion("Unknown")
                .targetJreVersion(50)
                .build());
        request.setInjectorConfig(InjectorConfig.builder()
                .urlPattern("/*")
                .build());
        request.setPacker(Packers.ScriptEngine);
        request.setShellToolConfig(Map.of(
                "pass", "pass",
                "key", "key",
                "headerName", "User-Agent",
                "headerValue", "hello"));
        ResponseEntity<MemShellGenerateResponse> response = restClient.post()
                .uri("/api/memshell/generate")
                .body(request)
                .retrieve()
                .toEntity(MemShellGenerateResponse.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    void responseHeaderProbeUsesNestedProbeConfig() {
        ResponseEntity<MemShellGenerateResponse> response = restClient.post()
                .uri("/api/memshell/generate")
                .body(Map.of(
                        "shellConfig", Map.of(
                                "server", Server.Tomcat,
                                "shellType", ShellType.FILTER,
                                "shellTool", ShellTool.Godzilla,
                                "probe", Map.of(
                                        "probeMethod", "ResponseHeader",
                                        "probeContent", "Bytecode",
                                        "respHeaderName", "X-Controller-Result")),
                        "injectorConfig", Map.of("urlPattern", "/*"),
                        "shellToolConfig", Map.of(),
                        "packer", ""))
                .retrieve()
                .toEntity(MemShellGenerateResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        ShellConfig resultConfig = response.getBody().getMemShellResult().getShellConfig();
        assertEquals(ProbeMethod.ResponseHeader, resultConfig.getProbe().getProbeMethod());
        assertEquals("X-Controller-Result", resultConfig.getProbe().getRespHeaderName());
        assertEquals(ObfuscationScope.ALL, resultConfig.getObfuscationScope());
    }

    @Test
    void obfuscationScopeIsAccepted() {
        ResponseEntity<MemShellGenerateResponse> response = restClient.post()
                .uri("/api/memshell/generate")
                .body(Map.of(
                        "shellConfig", Map.of(
                                "server", Server.Tomcat,
                                "shellType", ShellType.FILTER,
                                "shellTool", ShellTool.Command,
                                "obfuscationScope", "INJECTOR"),
                        "injectorConfig", Map.of("urlPattern", "/*"),
                        "shellToolConfig", Map.of("paramName", "cmd"),
                        "packer", ""))
                .retrieve()
                .toEntity(MemShellGenerateResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ObfuscationScope.INJECTOR,
                response.getBody().getMemShellResult().getShellConfig().getObfuscationScope());
    }

    @Test
    void blankPackerReturnsRawInjectorBase64() {
        MemShellGenerateRequest request = new MemShellGenerateRequest();
        request.setShellConfig(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Godzilla)
                .shrink(true)
                .debug(true)
                .lambdaSuffix(true)
                .serverVersion("Unknown")
                .targetJreVersion(50)
                .build());
        request.setInjectorConfig(InjectorConfig.builder()
                .urlPattern("/*")
                .build());
        // 不指定打包方式：直接输出注入器字节的 raw Base64
        request.setPacker("");

        ResponseEntity<MemShellGenerateResponse> response = restClient.post()
                .uri("/api/memshell/generate")
                .body(request)
                .retrieve()
                .toEntity(MemShellGenerateResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(response.getBody().getMemShellResult().getInjectorBytesBase64Str(),
                response.getBody().getPackResult());
    }

    @Test
    void springGzipJdk17PackerGetsExpressionClassName() {
        MemShellGenerateRequest request = new MemShellGenerateRequest();
        request.setShellConfig(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Godzilla)
                .serverVersion("Unknown")
                .targetJreVersion(50)
                .obfuscation(ObfuscationConfig.enabled())
                .build());
        // 模拟调用方没显式指定注入器类名：builder 默认值是词表名，但不在 Spring 要求的包下
        request.setInjectorConfig(InjectorConfig.builder().build());
        request.setPacker(Packers.SpELSpringGzipJDK17);

        ResponseEntity<MemShellGenerateResponse> response = restClient.post()
                .uri("/api/memshell/generate")
                .body(request)
                .retrieve()
                .toEntity(MemShellGenerateResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String injectorClassName = response.getBody().getMemShellResult()
                .getInjectorConfig().getInjectorClassName();
        assertTrue(PackerSupport.isSpringExpressionClassName(injectorClassName), injectorClassName);
        assertTrue(injectorClassName.endsWith("Utils"), injectorClassName);
        assertFalse(response.getBody().getMemShellResult().getShellConfig().getObfuscation().isEnabled());
    }

    /**
     * 参数 map 直通绑定层：写错的参数名会被明确拒绝，而不是像固定 DTO 那样被 Jackson 静默丢掉
     * （那样用户填的值不会生效，界面上却看不出来）。
     */
    @Test
    void unknownShellToolParamIsRejected() {
        MemShellGenerateRequest request = new MemShellGenerateRequest();
        request.setShellConfig(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Godzilla)
                .build());
        request.setPacker(Packers.ScriptEngine);
        request.setShellToolConfig(Map.of("godzillaPass", "pass"));

        RestClientResponseException exception = assertThrows(RestClientResponseException.class, () -> restClient.post()
                .uri("/api/memshell/generate")
                .body(request)
                .retrieve()
                .toEntity(MemShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("godzillaPass"),
                exception.getResponseBodyAsString());
        assertTrue(exception.getResponseBodyAsString().contains("pass"),
                exception.getResponseBodyAsString());
    }

    @Test
    void missingShellConfigIsRejectedAsBadRequest() {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class, () ->
                restClient.post()
                        .uri("/api/memshell/generate")
                        .body(Map.of("packer", ""))
                        .retrieve()
                        .toEntity(MemShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("shellConfig"),
                exception.getResponseBodyAsString());
    }

    @Test
    void unknownPackerIsRejectedAsBadRequest() {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class, () ->
                restClient.post()
                        .uri("/api/memshell/generate")
                        .body(Map.of(
                                "shellConfig", Map.of(),
                                "packer", "NoSuchPacker"))
                        .retrieve()
                        .toEntity(MemShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("NoSuchPacker"),
                exception.getResponseBodyAsString());
    }

    @Test
    void invalidCustomClassBase64IsRejectedAsBadRequest() {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class, () ->
                restClient.post()
                        .uri("/api/memshell/generate")
                        .body(Map.of(
                                "shellConfig", Map.of(
                                        "server", Server.Tomcat,
                                        "shellType", ShellType.FILTER,
                                        "shellTool", ShellTool.Custom),
                                "shellToolConfig", Map.of("shellClassBase64", "not-a-class"),
                                "packer", ""))
                        .retrieve()
                        .toEntity(MemShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("Base64"),
                exception.getResponseBodyAsString());
    }
}
