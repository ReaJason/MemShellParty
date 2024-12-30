package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.entity.Config;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2024/12/13
 */

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ConfigControllerIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testConfigEndpoint() {
        ResponseEntity<Config> response = restTemplate.getForEntity("/config", Config.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        Config config = response.getBody();
        assertNotNull(config);
        assertNotNull(config.getServers());
        assertNotNull(config.getCore());
        assertNotNull(config.getPackers());
    }
}