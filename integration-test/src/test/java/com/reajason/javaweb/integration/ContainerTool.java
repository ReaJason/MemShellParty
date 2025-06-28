package com.reajason.javaweb.integration;

import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ContainerTool {
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Path.of("..", "vul", "vul-webapp-jakarta", "build", "libs", "vul-webapp-jakarta.war").toAbsolutePath());
    public static final MountableFile warExpressionFile = MountableFile.forHostPath(Path.of("..", "vul", "vul-webapp-expression", "build", "libs", "vul-webapp-expression.war").toAbsolutePath());
    public static final MountableFile warDeserializeFile = MountableFile.forHostPath(Path.of("..", "vul", "vul-webapp-deserialize", "build", "libs", "vul-webapp-deserialize.war").toAbsolutePath());
    public static final MountableFile warFile = MountableFile.forHostPath(Path.of("..", "vul", "vul-webapp", "build", "libs", "vul-webapp.war").toAbsolutePath());
    public static final MountableFile springBoot2WarFile = MountableFile.forHostPath(Path.of("..", "vul", "vul-springboot2", "build", "libs", "vul-springboot2.war").toAbsolutePath());
    public static final Path neoGeorgDockerfile = Path.of("..", "asserts", "neoreg", "Dockerfile").toAbsolutePath();
    public static final Path springBoot1Dockerfile = Path.of("..", "vul", "vul-springboot1", "Dockerfile").toAbsolutePath();
    public static final Path springBoot2Dockerfile = Path.of("..", "vul", "vul-springboot2", "Dockerfile").toAbsolutePath();
    public static final Path springBoot2JettyDockerfile = Path.of("..", "vul", "vul-springboot2-jetty", "Dockerfile").toAbsolutePath();
    public static final Path springBoot2UndertowDockerfile = Path.of("..", "vul", "vul-springboot2-undertow", "Dockerfile").toAbsolutePath();
    public static final Path springBoot2WebfluxDockerfile = Path.of("..", "vul", "vul-springboot2-webflux", "Dockerfile").toAbsolutePath();
    public static final Path springBoot3Dockerfile = Path.of("..", "vul", "vul-springboot3", "Dockerfile").toAbsolutePath();
    public static final Path springBoot3WebfluxDockerfile = Path.of("..", "vul", "vul-springboot3-webflux", "Dockerfile").toAbsolutePath();

    public static final MountableFile jattachFile = MountableFile.forHostPath(Path.of("..", "asserts", "agent", "jattach-linux"));
    public static final MountableFile tomcatPid = MountableFile.forHostPath(Path.of("script", "tomcat_pid.sh"));
    public static final MountableFile tongweb8Pid = MountableFile.forHostPath(Path.of("script", "tongweb8_pid.sh"));
    public static final MountableFile resinPid = MountableFile.forHostPath(Path.of("script", "resin_pid.sh"));
    public static final MountableFile jbossPid = MountableFile.forHostPath(Path.of("script", "jboss_pid.sh"));
    public static final MountableFile glassfishPid = MountableFile.forHostPath(Path.of("script", "glassfish_pid.sh"));
    public static final MountableFile besPid = MountableFile.forHostPath(Path.of("script", "bes_pid.sh"));
    public static final MountableFile apusicPid = MountableFile.forHostPath(Path.of("script", "apusic_pid.sh"));
    public static final MountableFile jettyPid = MountableFile.forHostPath(Path.of("script", "jetty_pid.sh"));
    public static final MountableFile webspherePid = MountableFile.forHostPath(Path.of("script", "websphere_pid.sh"));
    public static final MountableFile weblogicPid = MountableFile.forHostPath(Path.of("script", "weblogic_pid.sh"));
    public static final MountableFile springbootPid = MountableFile.forHostPath(Path.of("script", "springboot_pid.sh"));
    public static final MountableFile javaPid = MountableFile.forHostPath(Path.of("script", "java_pid.sh"));

    public static String getUrl(GenericContainer<?> container) {
        int port = container.getMappedPort(8080);
        String url = "http://127.0.0.1:" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
