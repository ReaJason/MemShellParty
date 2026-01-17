package com.reajason.javaweb.integration;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.packer.Packers;
import lombok.Builder;
import lombok.Getter;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.tuple.Triple;
import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/9/19
 */
@Getter
@Builder
public class ContainerTestConfig {
    private final String imageName;
    private final Path dockerfilePath;
    private final String command;

    private final String server;
    private final String serverVersion;
    @Builder.Default
    private final int targetJdkVersion = Opcodes.V1_8;
    private final Integer probeTargetJdkVersion;

    @Builder.Default
    private final int exposedPort = 8080;
    @Builder.Default
    private final String contextPath = "/app";
    @Builder.Default
    private final String healthCheckPath = "/app";
    private final WaitStrategy waitStrategy;

    private final MountableFile warFile;
    private final String warDeployPath;

    private final MountableFile jarFile;
    private final String jarDeployPath;

    @Builder.Default
    private final MountableFile jattachFile = ContainerTool.jattachFile;
    private final MountableFile pidScript;

    private final List<String> supportedShellTypes;
    private final List<Packers> testPackers;
    private final List<String> probeShellTypes;
    private final List<Triple<String, String, Packers>> unSupportedCases;
    private final List<String> unSupportedShellTools;

    @Builder.Default
    private final boolean assertLogs = true;
    @Builder.Default
    private final boolean logContainerOutput = true;
    @Builder.Default
    private final long logDelayMillis = 0L;
    @Builder.Default
    private final boolean privilegedMode = false;
    @Builder.Default
    private final String networkAlias = "app";
    private final Map<String, String> env;
    @Builder.Default
    private final boolean jakarta = false;
    @Builder.Default
    private final boolean enableJspPackerTest = true;

    public static ContainerTestConfigBuilder tomcat(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Tomcat)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/usr/local/tomcat/webapps/app.war")
                .pidScript(ContainerTool.tomcatPid);
    }

    public static ContainerTestConfigBuilder jetty(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Jetty)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/var/lib/jetty/webapps/app.war")
                .pidScript(ContainerTool.jettyPid);
    }

    public static ContainerTestConfigBuilder resin(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Resin)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.resinPid);
    }

    public static ContainerTestConfigBuilder jboss(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.JBoss)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.jbossPid);
    }

    public static ContainerTestConfigBuilder undertow(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Undertow)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.jbossPid);
    }

    public static ContainerTestConfigBuilder glassFish(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.glassfishPid);
    }

    public static ContainerTestConfigBuilder webLogic(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.WebLogic)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.weblogicPid)
                .exposedPort(7001);
    }

    public static ContainerTestConfigBuilder webSphere(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.WebSphere)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .pidScript(ContainerTool.webspherePid)
                .exposedPort(9080)
                .privilegedMode(true);
    }
}
