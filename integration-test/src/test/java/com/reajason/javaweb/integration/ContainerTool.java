package com.reajason.javaweb.integration;

import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Paths;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ContainerTool {
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Paths.get("../vul-webapp-jakarta/build/libs/vul-webapp-jakarta.war").toAbsolutePath());
    public static final MountableFile warFile = MountableFile.forHostPath(Paths.get("../vul-webapp/build/libs/vul-webapp.war").toAbsolutePath());


    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
