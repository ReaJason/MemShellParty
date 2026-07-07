package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
        assertEquals(ServerFactory.getSupportedServers(), List.copyOf(response.getBody().keySet()));
    }

    @Test
    public void testConfigServersEndpoint() {
        ResponseEntity<Map<String, Object>> response = restClient.get()
                .uri("/api/config/servers")
                .retrieve()
                .toEntity(MAP_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ServerFactory.getSupportedServers(), List.copyOf(response.getBody().keySet()));
    }

    @Test
    public void testConfigPackersEndpoint() {
        ResponseEntity<List<String>> response = restClient.get()
                .uri("/api/config/packers")
                .retrieve()
                .toEntity(STRING_LIST_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    public void testConfigProbeResponseBodyServersEndpoint() {
        ResponseEntity<List<String>> response = restClient.get()
                .uri("/api/config/probe/response-body/servers")
                .retrieve()
                .toEntity(STRING_LIST_TYPE);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ResponseBodyGenerator.getSupportedServers(), response.getBody());
    }
}
