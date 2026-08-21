package com.reajason.javaweb.integration.probe.springwebmvc;

import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2026/08/21
 */
@Testcontainers
public class SpringBoot4ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig
            .springboot("eclipse-temurin:21.0.11_10-jdk", ContainerTool.springBoot4JarFile)
            .expectedJdkVersion("JDK|21.0.11|65")
            .targetJdkVersion(Opcodes.V21)
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
