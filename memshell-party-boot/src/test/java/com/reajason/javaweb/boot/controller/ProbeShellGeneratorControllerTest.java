package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.packer.PackerSupport;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * probeConfig / probeContentConfig 是「要生成什么」的全部信息，没有可以补的默认值：
 * 缺了要明确报缺哪个字段，而不是在 parseProbeContentConfig 解引用时 NPE。
 *
 * @author ReaJason
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProbeShellGeneratorControllerTest {

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
    void missingProbeConfigIsRejectedWithFieldName() {
        assertRejectedWith(new ProbeShellGenerateRequest(), "probeMethod");
    }

    @Test
    void missingProbeContentConfigIsRejectedWithFieldName() {
        ProbeShellGenerateRequest request = new ProbeShellGenerateRequest();
        request.setProbeConfig(ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .build());
        assertRejectedWith(request, "probeContentConfig");
    }

    @Test
    void springGzipJdk17PackerGetsExpressionClassName() throws Exception {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseBody",
                        "probeContent", "Command",
                        "obfuscation", Map.of("enabled", true)),
                "probeContentConfig", Map.of("server", "Tomcat"),
                "packer", Packers.SpELSpringGzipJDK17);

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        JsonNode result = new ObjectMapper().readTree(response.getBody());
        String className = result.at("/probeShellResult/shellClassName").asText();
        assertTrue(PackerSupport.isSpringExpressionClassName(className), className);
        assertTrue(className.endsWith("Utils"), className);
        assertFalse(result.at("/probeShellResult/probeConfig/obfuscation/enabled").asBoolean(true));
    }

    @Test
    void knownServerDetectionOmitsUnusedRequestParam() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseBody",
                        "probeContent", "Server"),
                "probeContentConfig", Map.of(
                        "server", "Tomcat",
                        "reqParamName", "unused"),
                "packer", Packers.DefaultBase64);

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().contains("\"reqParamName\""), response.getBody());
    }

    @Test
    void unknownServerDetectionKeepsRequestParam() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseBody",
                        "probeContent", "Server"),
                "probeContentConfig", Map.of(
                        "server", "Unknown",
                        "reqParamName", "probe"),
                "packer", Packers.DefaultBase64);

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("\"reqParamName\":\"probe\""), response.getBody());
    }

    @Test
    void responseHeaderProbeDefaultsToXPrefixedName() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseHeader",
                        "probeContent", "Command"),
                "probeContentConfig", Map.of("server", "Tomcat"),
                "packer", Packers.DefaultBase64);

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("\"respHeaderName\":\"X-"), response.getBody());
    }

    @Test
    void responseHeaderProbeKeepsExplicitName() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseHeader",
                        "probeContent", "Command"),
                "probeContentConfig", Map.of(
                        "server", "Tomcat",
                        "respHeaderName", "X-Result"),
                "packer", Packers.DefaultBase64);

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("\"respHeaderName\":\"X-Result\""), response.getBody());
    }

    @Test
    void invalidResponseHeaderNameIsRejected() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseHeader",
                        "probeContent", "Command"),
                "probeContentConfig", Map.of(
                        "server", "Tomcat",
                        "respHeaderName", "X-Bad Header"),
                "packer", Packers.DefaultBase64);

        RestClientResponseException exception = assertThrows(RestClientResponseException.class,
                () -> restClient.post()
                        .uri("/api/probe/generate")
                        .body(body)
                        .retrieve()
                        .toEntity(ProbeShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("invalid response header name"),
                exception.getResponseBodyAsString());
    }

    @Test
    void unknownProbeMethodIsRejectedAsBadRequest() {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class,
                () -> restClient.post()
                        .uri("/api/probe/generate")
                        .body(Map.of(
                                "probeConfig", Map.of("probeMethod", "Bogus"),
                                "probeContentConfig", Map.of()))
                        .retrieve()
                        .toEntity(ProbeShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains("Malformed request body"),
                exception.getResponseBodyAsString());
    }

    private void assertRejectedWith(ProbeShellGenerateRequest request, String expectedField) {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class,
                () -> restClient.post()
                        .uri("/api/probe/generate")
                        .body(request)
                        .retrieve()
                        .toEntity(ProbeShellGenerateResponse.class));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains(expectedField),
                exception.getResponseBodyAsString());
    }
}
