package com.reajason.javaweb.integration.probe.weblogic;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
@Testcontainers
public class WebLogic14120ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.weblogic(
                    "reajason/weblogic:14.1.2.0-jdk17",
                    "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
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
