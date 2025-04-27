package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractShell;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@RestController
@RequestMapping("/config")
@CrossOrigin("*")
public class ConfigController {

    @RequestMapping("/servers")
    public Map<String, List<String>> getServers() {
        Map<String, List<String>> servers = new LinkedHashMap<>();
        for (Server server : Server.values()) {
            if (server.getShell() != null) {
                Set<String> supportedShellTypes = server.getShell().getShellInjectorMapping().getSupportedShellTypes();
                servers.put(server.name(), supportedShellTypes.stream().toList());
            }
        }
        return servers;
    }

    @RequestMapping("/packers")
    public List<String> getPackers() {
        return Arrays.stream(Packers.values())
                .filter(packers -> packers.getParentPacker() == null)
                .map(Packers::name).toList();
    }

    @RequestMapping
    public Map<String, Map<?, ?>> config() {
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
        return coreMap;
    }

    @GetMapping("/command/encryptors")
    public List<CommandConfig.Encryptor> getCommandEncryptors() {
        return Arrays.stream(CommandConfig.Encryptor.values()).toList();
    }
}