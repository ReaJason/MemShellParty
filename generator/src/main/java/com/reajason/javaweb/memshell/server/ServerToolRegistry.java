package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.generator.ValveGenerator;

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

                if (ShellType.LISTENER.equals(shellType) || ShellType.JAKARTA_LISTENER.equals(shellType)) {
                    shellClass = ListenerGenerator.generateListenerShellClass(shell.getListenerInterceptor(), shellClass);
                }
                boolean isValve = (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType));
                if (isValve && shell instanceof TongWeb6Shell) {
                    shellClass = ValveGenerator.generateValveClass(ValveGenerator.TONGWEB6_VALVE_PACKAGE, shellClass);
                }

                if (isValve && shell instanceof TongWeb7Shell) {
                    shellClass = ValveGenerator.generateValveClass(ValveGenerator.TONGWEB7_VALVE_PACKAGE, shellClass);
                }

                if (isValve && shell instanceof TongWeb8Shell) {
                    shellClass = ValveGenerator.generateValveClass(ValveGenerator.TONGWEB8_VALVE_PACKAGE, shellClass);
                }

                if (isValve && shell instanceof BesShell) {
                    shellClass = ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, shellClass);
                }

                toolMappingBuilder.addShellClass(shellType, shellClass);
            }
            shell.addToolMapping(shellTool, toolMappingBuilder.build());
        }
    }
}