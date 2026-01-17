package com.reajason.javaweb.integration.probe.springwebmvc;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.junitpioneer.jupiter.RetryingTest;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.reajason.javaweb.integration.ContainerTool.springBoot2WarFile;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
public class SpringBoot2WarContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.tomcat("tomcat:8-jre8")
            .warFile(springBoot2WarFile)
            .expectedJdkVersion("JRE|1.8.0_402|52")
            .targetJdkVersion(Opcodes.V1_6)
            .supportsSpringWebMvc(true)
            .supportsScriptEngine(false)
            .supportsFilterProbe(false)
            .supportsBytecodeWithoutPrefix(false)
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

    @Override
    @RetryingTest(3)
    protected void testJDK() {
        doTestJDK();
    }
}
