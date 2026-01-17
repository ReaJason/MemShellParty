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
 * @since 2024/12/22
 */
@Testcontainers
public class SpringBoot2UndertowContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig
            .springbootUndertow("eclipse-temurin:8u472-b08-jdk", ContainerTool.springBoot2UndertowJarFile)
            .expectedJdkVersion("JDK|1.8.0_472|52")
            .targetJdkVersion(Opcodes.V1_6)
            .supportsSpringWebMvc(false)
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
