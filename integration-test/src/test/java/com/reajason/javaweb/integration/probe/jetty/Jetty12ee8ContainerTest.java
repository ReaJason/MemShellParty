package com.reajason.javaweb.integration.probe.jetty;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
@Testcontainers
public class Jetty12ee8ContainerTest extends AbstractProbeContainerTest {

    // Jetty 12 ee8 uses javax.servlet (not Jakarta), so we use jetty() factory
    private static final ProbeTestConfig CONFIG = ProbeTestConfig.jetty("reajason/jetty:12.0-jre21-ee8")
            .expectedJdkVersion("JRE|21.0.9|65")
            .targetJdkVersion(Opcodes.V21)
            .supportsBytecode(false)
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
