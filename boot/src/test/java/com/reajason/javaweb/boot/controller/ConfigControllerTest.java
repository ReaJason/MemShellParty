package com.reajason.javaweb.boot.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
class ConfigControllerTest {
    @Test
    void getConfig() {
        ConfigController configController = new ConfigController();
        ResponseEntity<?> config = configController.config();
        Object body = config.getBody();
        assertNotNull(body);
        System.out.println(body);
    }
}