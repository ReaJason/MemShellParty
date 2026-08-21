package com.reajason.javaweb.integration.probe.springwebflux;

import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2026/08/21
 */
@Testcontainers
public class SpringBoot4WebFluxContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig
            .springwebflux("eclipse-temurin:21.0.11_10-jdk", ContainerTool.springBoot4WebfluxJarFile)
            .expectedJdkVersion("JDK|21.0.11|65")
            .build();

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG);

    @Override
    protected ProbeTestConfig getConfig() {
        return CONFIG;
    }

    @Override
    protected GenericContainer<?> getContainer() {
        return container;
    }
}
