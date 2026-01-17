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
public class GlassFish7ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.glassfishJakarta(
                    "reajason/glassfish:7.0.20-jdk17",
                    "/usr/local/glassfish7/glassfish/domains/domain1/autodeploy/app.war")
            .expectedJdkVersion("JDK|17.0.2|61")
            .targetJdkVersion(Opcodes.V17)
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
