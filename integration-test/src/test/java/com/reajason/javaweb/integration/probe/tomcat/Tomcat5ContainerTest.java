package com.reajason.javaweb.integration.probe.tomcat;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.junitpioneer.jupiter.RetryingTest;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Testcontainers
public class Tomcat5ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.tomcat("reajason/tomcat:5-jdk6")
            .expectedJdkVersion("JDK|1.6.0_45|50")
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

    // 存在首次请求，Tomcat 无法通过 req.getParameter 拿到参数的情况，因此需要重试
    @Override
    @RetryingTest(3)
    protected void testJDK() {
        doTestJDK();
    }
}
