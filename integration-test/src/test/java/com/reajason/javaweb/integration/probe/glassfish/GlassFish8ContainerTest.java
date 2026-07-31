package com.reajason.javaweb.integration.probe.glassfish;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class GlassFish8ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.glassfishJakarta(
                    "reajason/glassfish:8.0.3-jdk21",
                    "/usr/local/glassfish8/glassfish/domains/domain1/autodeploy/app.war")
            .expectedJdkVersion("JDK|21.0.11|65")
            .targetJdkVersion(Opcodes.V21)
            .waitStrategy(Wait.forLogMessage(".*JMXService.*", 1))
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
