package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.entity.Config;
import com.reajason.javaweb.memshell.AbstractShell;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packers;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@RestController
@RequestMapping("/config")
@CrossOrigin("*")
public class ConfigController {
    @RequestMapping
    public ResponseEntity<?> config() {
        Map<String, Map<?, ?>> coreMap = new HashMap<>(16);
        for (Server value : Server.values()) {
            AbstractShell shell = value.getShell();
            if (shell == null) {
                continue;
            }
            ShellTool[] supportedShellTools = ShellTool.values();
            Map<String, List<String>> map = new HashMap<>(16);
            for (ShellTool shellTool : supportedShellTools) {
                List<String> supportedShellTypes = shell.getSupportedShellTypes(shellTool);
                if (supportedShellTypes.isEmpty()) {
                    continue;
                }
                map.put(shellTool.name(), supportedShellTypes);
            }
            coreMap.put(value.name(), map);
        }
        Config config = new Config();
        config.setServers(
                Arrays.stream(Server.values())
                        .filter(s -> s.getShell() != null)
                        .map(Server::name)
                        .collect(Collectors.toList())
        );
        config.setCore(coreMap);
        config.setPackers(Arrays.stream(Packers.values()).map(Packers::name).toList());
        return ResponseEntity.ok(config);
    }
}