package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.vo.CommandConfigVO;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.Packers;
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
@RequestMapping("/api/config")
@CrossOrigin("*")
public class ConfigController {

    @RequestMapping("/servers")
    public Map<String, List<String>> getServers() {
        Map<String, List<String>> servers = new LinkedHashMap<>();
        List<String> supportedServers = ServerFactory.getSupportedServers();
        for (String supportedServer : supportedServers) {
            Set<String> supportedShellTypes = ServerFactory.getServer(supportedServer)
                    .getShellInjectorMapping().getSupportedShellTypes();
            servers.put(supportedServer, supportedShellTypes.stream().toList());
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
        List<String> supportedServers = ServerFactory.getSupportedServers();
        for (String supportedServer : supportedServers) {
            AbstractServer server = ServerFactory.getServer(supportedServer);
            Map<String, Set<String>> map = new LinkedHashMap<>(16);
            for (String shellTool : server.getSupportedShellTools()) {
                Set<String> supportedShellTypes = server.getSupportedShellTypes(shellTool);
                if (supportedShellTypes.isEmpty()) {
                    continue;
                }
                map.put(shellTool, supportedShellTypes);
            }
            coreMap.put(supportedServer, map);
        }
        return coreMap;
    }

    @GetMapping("/command/configs")
    public CommandConfigVO getCommandConfigs() {
        CommandConfigVO commandConfigVO = new CommandConfigVO();
        commandConfigVO.setEncryptors(Arrays.stream(CommandConfig.Encryptor.values()).toList());
        commandConfigVO.setImplementationClasses(Arrays.stream(CommandConfig.ImplementationClass.values()).toList());
        return commandConfigVO;
    }
}