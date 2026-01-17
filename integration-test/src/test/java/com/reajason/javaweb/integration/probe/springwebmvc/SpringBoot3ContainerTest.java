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
public class SpringBoot3ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig
            .springboot("eclipse-temurin:17.0.17_10-jdk", ContainerTool.springBoot3JarFile)
            .expectedJdkVersion("JDK|17.0.17|61")
            .targetJdkVersion(Opcodes.V17)
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
