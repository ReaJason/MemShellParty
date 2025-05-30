package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;

import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ServerToolRegistry {

    public static void addToolMapping(ShellTool shellTool, ToolMapping toolMapping) {
        Map<String, Class<?>> rawToolMapping = toolMapping.getShellClassMap();
        for (Server value : Server.values()) {
            AbstractShell shell = value.getShell();
            InjectorMapping shellInjectorMapping = shell.getShellInjectorMapping();
            Set<String> injectorSupportedShellTypes = shellInjectorMapping.getSupportedShellTypes();
            ToolMapping.ToolMappingBuilder toolMappingBuilder = ToolMapping.builder();

            for (String shellType : injectorSupportedShellTypes) {
                Class<?> shellClass = rawToolMapping.get(shellType);
                if (shellClass == null) {
                    continue;
                }
                toolMappingBuilder.addShellClass(shellType, shellClass);
            }
            shell.addToolMapping(shellTool, toolMappingBuilder.build());
        }
    }
}