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
public class GlassFish4ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.glassfish(
                    "reajason/glassfish:4.1.2-quick",
                    "/usr/local/glassfish4/glassfish/domains/domain1/autodeploy/app.war")
            .expectedJdkVersion("JDK|1.8.0_271|52")
            .targetJdkVersion(Opcodes.V1_6)
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
