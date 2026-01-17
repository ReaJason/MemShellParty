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
public class WebLogic1036ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.weblogic(
                    "reajason/weblogic:10.3.6",
                    "/opt/oracle/wls1036/user_projects/domains/base_domain/autodeploy/app.war")
            .expectedJdkVersion("JDK|1.8.0_342|52")
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
