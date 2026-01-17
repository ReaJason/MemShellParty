package com.reajason.javaweb.integration.probe.glassfish;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class GlassFish6ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.glassfishJakarta(
                    "reajason/glassfish:6.2.6-jdk11",
                    "/usr/local/glassfish6/glassfish/domains/domain1/autodeploy/app.war")
            .expectedJdkVersion("JDK|11.0.16|55")
            .targetJdkVersion(Opcodes.V11)
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
