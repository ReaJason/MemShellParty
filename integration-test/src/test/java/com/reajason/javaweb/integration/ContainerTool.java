package com.reajason.javaweb.integration;

import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ContainerTool {
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Paths.get("../vul/vul-webapp-jakarta/build/libs/vul-webapp-jakarta.war").toAbsolutePath());
    public static final MountableFile warExpressionFile = MountableFile.forHostPath(Paths.get("../vul/vul-webapp-expression/build/libs/vul-webapp-expression.war").toAbsolutePath());
    public static final MountableFile warFile = MountableFile.forHostPath(Paths.get("../vul/vul-webapp/build/libs/vul-webapp.war").toAbsolutePath());
    public static final MountableFile springBoot2WarFile = MountableFile.forHostPath(Paths.get("../vul/vul-springboot2/build/libs/vul-springboot2.war").toAbsolutePath());
    public static final Path springBoot2Dockerfile = Paths.get("../vul/vul-springboot2/Dockerfile").toAbsolutePath();
    public static final Path springBoot2WebfluxDockerfile = Paths.get("../vul/vul-springboot2-webflux/Dockerfile").toAbsolutePath();
    public static final Path springBoot3Dockerfile = Paths.get("../vul/vul-springboot3/Dockerfile").toAbsolutePath();
    public static final Path springBoot3WebfluxDockerfile = Paths.get("../vul/vul-springboot3-webflux/Dockerfile").toAbsolutePath();

    public static final MountableFile jattachFile = MountableFile.forHostPath(Path.of("../asserts/agent/jattach-linux"));
    public static final MountableFile tomcatPid = MountableFile.forHostPath(Path.of("script/tomcat_pid.sh"));

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
