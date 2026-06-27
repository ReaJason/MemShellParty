package com.reajason.javaweb.integration.memshell.dubbo;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

final class DubboContainerFactory {

    private DubboContainerFactory() {
    }

    static GenericContainer<?> buildProvider(DubboProviderScenario scenario) {
        String jarPath = providerJarPath(scenario.providerJarProperty());
        GenericContainer<?> container = new GenericContainer<>(scenario.imageName())
                .withCopyFileToContainer(MountableFile.forHostPath(jarPath), "/app/app.jar")
                .withWorkingDirectory("/app")
                .withExposedPorts(exposedPorts(scenario))
                .waitingFor(Wait.forLogMessage(".*Provider started.*", 1)
                        .withStartupTimeout(Duration.ofMinutes(3)));

        if ("alibaba".equals(scenario.clientKind())) {
            container.withCommand("java", "-jar", "/app/app.jar");
        } else {
            container.withCommand(
                    "java",
                    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                    "--add-opens", "java.base/java.math=ALL-UNNAMED",
                    "-jar", "/app/app.jar"
            );
        }
        return container;
    }

    private static Integer[] exposedPorts(DubboProviderScenario scenario) {
        return scenario.commandTargets().stream()
                .map(DubboProtocolTarget::port)
                .distinct()
                .toArray(Integer[]::new);
    }

    private static String providerJarPath(String propertyName) {
        String value = System.getProperty(propertyName);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException("missing " + propertyName + " system property");
        }
        Path path = Path.of(value);
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("provider jar does not exist: " + path);
        }
        return path.toAbsolutePath().toString();
    }
}
