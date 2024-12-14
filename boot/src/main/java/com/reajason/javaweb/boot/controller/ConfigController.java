package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.entity.Config;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.deserialize.PayloadType;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.packer.Packer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@RestController("/config")
public class ConfigController {
    @RequestMapping
    public ResponseEntity<?> config() {
        Map<String, Map<?, ?>> coreMap = new HashMap<>(16);
        List<String> servers = new ArrayList<>();
        for (Server value : Server.values()) {
            AbstractShell shell = value.getShell();
            if (shell != null) {
                List<ShellTool> supportedShellTools = shell.getSupportedShellTools();
                Map<String, List<String>> map = new HashMap<>(16);
                for (ShellTool shellTool : supportedShellTools) {
                    List<String> supportedShellTypes = shell.getSupportedShellTypes(shellTool);
                    map.put(shellTool.name(), supportedShellTypes);
                }
                servers.add(value.name());
                coreMap.put(value.name(), map);
            }
        }
        Config config = new Config();
        config.setServers(servers);
        config.setCore(coreMap);
        Map<String, Map<?, ?>> packerMap = new HashMap<>(16);
        for (Packer.INSTANCE value : Packer.INSTANCE.values()) {
            if (value.equals(Packer.INSTANCE.Deserialize)) {
                packerMap.put(value.name(), Map.of("payloads", PayloadType.values()));
            } else {
                packerMap.put(value.name(), null);
            }
        }
        config.setPacker(packerMap);
        return ResponseEntity.ok(config);
    }
}