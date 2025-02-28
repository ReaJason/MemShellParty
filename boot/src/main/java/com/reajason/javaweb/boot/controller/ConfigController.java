package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.entity.Config;
import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.server.AbstractShell;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
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
            Map<String, Set<String>> map = new LinkedHashMap<>(16);
            for (ShellTool shellTool : shell.getSupportedShellTools()) {
                Set<String> supportedShellTypes = shell.getSupportedShellTypes(shellTool);
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
        config.setPackers(
                Arrays.stream(Packers.values())
                        .filter(packers -> packers.getParentPacker() == null)
                        .map(Packers::name).toList()
        );
        return ResponseEntity.ok(config);
    }
}