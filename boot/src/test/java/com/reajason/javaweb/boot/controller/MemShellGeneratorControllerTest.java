package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.Packers;
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
 * @since 2025/9/16
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MemShellGeneratorControllerTest {

    @Autowired
    TestRestTemplate restTemplate;

    @Test
    void generateShell() {
        MemShellGenerateRequest request = new MemShellGenerateRequest();
        request.setShellConfig(ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Godzilla)
                .shrink(true)
                .debug(true)
                .serverVersion("Unknown")
                .targetJreVersion(50)
                .build());
        request.setInjectorConfig(InjectorConfig.builder()
                .urlPattern("/*")
                .build());
        request.setPacker(Packers.ScriptEngine);
        MemShellGenerateRequest.ShellToolConfigDTO shellToolConfigDTO = new MemShellGenerateRequest.ShellToolConfigDTO();
        shellToolConfigDTO.setGodzillaKey("key");
        shellToolConfigDTO.setGodzillaPass("pass");
        shellToolConfigDTO.setHeaderName("User-Agent");
        shellToolConfigDTO.setHeaderValue("hello");
        request.setShellToolConfig(shellToolConfigDTO);
        ResponseEntity<MemShellGenerateResponse> response = restTemplate.postForEntity(
                "/memshell/generate", request, MemShellGenerateResponse.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }
}