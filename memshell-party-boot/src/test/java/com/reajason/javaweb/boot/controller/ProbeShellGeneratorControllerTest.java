package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
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

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void springGzipJdk17PackerGetsExpressionClassName() {
        Map<String, Object> body = Map.of(
                "probeConfig", Map.of(
                        "probeMethod", "ResponseBody",
                        "probeContent", "Command"),
                "probeContentConfig", Map.of("server", "Tomcat"),
                "packer", "SpELSpringGzipJDK17");

        ResponseEntity<String> response = restClient.post()
                .uri("/api/probe/generate")
                .body(body)
                .retrieve()
                .toEntity(String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("\"shellClassName\":\"org.springframework.expression."),
                response.getBody());
        assertTrue(response.getBody().contains("Utils\""), response.getBody());
    }

    private void assertRejectedWith(ProbeShellGenerateRequest request, String expectedField) {
        RestClientResponseException exception = assertThrows(RestClientResponseException.class,
                () -> restClient.post()
                        .uri("/api/probe/generate")
                        .body(request)
                        .retrieve()
                        .toEntity(ProbeShellGenerateResponse.class));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertTrue(exception.getResponseBodyAsString().contains(expectedField),
                exception.getResponseBodyAsString());
    }
}
