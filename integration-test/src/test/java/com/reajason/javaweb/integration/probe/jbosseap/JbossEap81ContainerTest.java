package com.reajason.javaweb.integration.probe.jbosseap;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@Testcontainers
public class JbossEap81ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.jbossEapJakarta(
                    "reajason/jboss:eap-8.1-jdk17",
                    "/usr/local/jboss/standalone/deployments/app.war")
            .expectedJdkVersion("JDK|17.0.15|61")
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
