package com.reajason.javaweb.integration.probe.wildfly;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * <a href="https://hub.docker.com/r/jboss/wildfly/tags">Wildfly - DockerHub</a>
 * <a href="https://quay.io/repository/wildfly/wildfly?tab=tags">Wildfly - Quay</a>
 *
 * @author ReaJason
 * @since 2024/12/10
 */
@Testcontainers
public class Wildfly9ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig
            .wildfly("jboss/wildfly:9.0.1.Final")
            .expectedJdkVersion("JDK|1.8.0_191|52")
            .targetJdkVersion(Opcodes.V1_8)
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
