package com.reajason.javaweb.integration.probe.websphere;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
public class OpenLiberty25ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.openLiberty("open-liberty:25.0.0.12-full-java17-openj9")
            .expectedJdkVersion("JRE|17.0.17|61")
            .targetJdkVersion(Opcodes.V1_8)
            .waitStrategy(Wait.forHttp("/app/").forPort(9080).withStartupTimeout(Duration.ofMinutes(5)))
            .privilegedMode(true)
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
