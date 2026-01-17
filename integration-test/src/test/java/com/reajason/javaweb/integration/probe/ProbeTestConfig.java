package com.reajason.javaweb.integration.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ContainerTool;
import lombok.Builder;
import lombok.Getter;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;

/**
 * Configuration class for probe container tests.
 * Uses builder pattern similar to ContainerTestConfig.
 *
 * @author ReaJason
 * @since 2024/12/4
 */
@Getter
@Builder
public class ProbeTestConfig {
    private final String imageName;
    private final String server;
    private final String expectedJdkVersion;

    @Builder.Default
    private final int targetJdkVersion = Opcodes.V1_8;

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

    private final String command;

    @Builder.Default
    private final boolean privilegedMode = false;

    @Builder.Default
    private final boolean supportsScriptEngine = false;

    @Builder.Default
    private final boolean supportsFilterProbe = true;

    @Builder.Default
    private final boolean supportsCommand = true;

    @Builder.Default
    private final boolean supportsBytecode = true;

    @Builder.Default
    private final boolean supportsSpringWebMvc = false;

    @Builder.Default
    private final boolean supportsBytecodeWithoutPrefix = false;

    @Builder.Default
    private final boolean jakarta = false;

    // Factory methods for common server configurations

    public static ProbeTestConfigBuilder tomcat(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Tomcat)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/usr/local/tomcat/webapps/app.war")
                .supportsScriptEngine(true)
                .supportsBytecodeWithoutPrefix(true);
    }

    public static ProbeTestConfigBuilder tomcatJakarta(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Tomcat)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath("/usr/local/tomcat/webapps/app.war")
                .supportsBytecodeWithoutPrefix(true)
                .jakarta(true);
    }

    public static ProbeTestConfigBuilder jetty(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Jetty)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/var/lib/jetty/webapps/app.war");
    }

    public static ProbeTestConfigBuilder jettyJakarta(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Jetty)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath("/var/lib/jetty/webapps/app.war")
                .jakarta(true)
                .supportsBytecode(false);
    }

    public static ProbeTestConfigBuilder jettyOld(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Jetty)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder glassfish(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder glassfishJakarta(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath(warDeployPath)
                .jakarta(true);
    }

    public static ProbeTestConfigBuilder payara(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder payaraJakarta(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath(warDeployPath)
                .jakarta(true);
    }

    public static ProbeTestConfigBuilder weblogic(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.WebLogic)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .exposedPort(7001);
    }

    public static ProbeTestConfigBuilder websphere(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.WebSphere)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath)
                .exposedPort(9080)
                .privilegedMode(true);
    }

    public static ProbeTestConfigBuilder openLiberty(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.WebSphere)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/config/dropins/app.war")
                .exposedPort(9080);
    }

    public static ProbeTestConfigBuilder wildfly(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Undertow)
                .warFile(ContainerTool.warFile)
                .warDeployPath("/opt/jboss/wildfly/standalone/deployments/app.war");
    }

    public static ProbeTestConfigBuilder wildflyJakarta(String imageName) {
        return builder()
                .imageName(imageName)
                .server(Server.Undertow)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath("/opt/jboss/wildfly/standalone/deployments/app.war")
                .jakarta(true);
    }

    public static ProbeTestConfigBuilder jboss(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.JBoss)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder jbossEap(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Undertow)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder jbossEapJakarta(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Undertow)
                .warFile(ContainerTool.warJakartaFile)
                .warDeployPath(warDeployPath)
                .jakarta(true);
    }

    public static ProbeTestConfigBuilder resin(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Resin)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder springboot(String imageName, MountableFile jarFile) {
        return builder()
                .imageName(imageName)
                .jarFile(jarFile)
                .jarDeployPath("/app/app.jar")
                .command("java -jar /app/app.jar")
                .server(Server.Tomcat)
                .contextPath("")
                .healthCheckPath("/test")
                .supportsFilterProbe(false)
                .supportsSpringWebMvc(true);
    }

    public static ProbeTestConfigBuilder springbootJetty(String imageName, MountableFile jarFile) {
        return builder()
                .imageName(imageName)
                .jarFile(jarFile)
                .jarDeployPath("/app/app.jar")
                .command("java -jar /app/app.jar")
                .server(Server.Jetty)
                .contextPath("")
                .healthCheckPath("/test")
                .supportsFilterProbe(false)
                .supportsSpringWebMvc(true);
    }

    public static ProbeTestConfigBuilder springbootUndertow(String imageName, MountableFile jarFile) {
        return builder()
                .imageName(imageName)
                .jarFile(jarFile)
                .jarDeployPath("/app/app.jar")
                .command("java -jar /app/app.jar")
                .server(Server.Undertow)
                .contextPath("")
                .healthCheckPath("/test")
                .supportsFilterProbe(false)
                .supportsSpringWebMvc(true);
    }

    public static ProbeTestConfigBuilder springwebflux(String imageName, MountableFile jarFile) {
        return builder()
                .imageName(imageName)
                .jarFile(jarFile)
                .jarDeployPath("/app/app.jar")
                .command("java -jar /app/app.jar")
                .server(Server.SpringWebFlux)
                .contextPath("")
                .healthCheckPath("/test")
                .supportsFilterProbe(false)
                .supportsCommand(false)
                .supportsBytecode(false);
    }

    public static ProbeTestConfigBuilder tongweb(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.TongWeb)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder bes(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.BES)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder apusic(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.Apusic)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder inforsuite(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.InforSuite)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }

    public static ProbeTestConfigBuilder primeton(String imageName, String warDeployPath) {
        return builder()
                .imageName(imageName)
                .server(Server.GlassFish)
                .warFile(ContainerTool.warFile)
                .warDeployPath(warDeployPath);
    }
}
