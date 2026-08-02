package com.reajason.javaweb.integration.probe.payara;

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
public class Payara7202606ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.payaraJakarta(
                    "payara/server-web:7.2026.6",
                    "/opt/payara/deployments/app.war")
            .expectedJdkVersion("JDK|21.0.11|65")
            .targetJdkVersion(Opcodes.V21)
            .waitStrategy(Wait.forHttp("/app/").forPort(8080).forStatusCode(200))
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
