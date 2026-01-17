package com.reajason.javaweb.integration.probe.jbossas;

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
public class Jboss423ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.jboss(
                    "reajason/jboss:4-jdk6",
                    "/usr/local/jboss/server/default/deploy/app.war")
            .expectedJdkVersion("JDK|1.6.0_45|50")
            .targetJdkVersion(Opcodes.V1_6)
            .build();

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG)
            .withEnv("JAVA_OPTS", "-Xms128m -Xmx512m -XX:MaxPermSize=128M -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000");

    @Override
    protected ProbeTestConfig getConfig() {
        return CONFIG;
    }

    @Override
    protected GenericContainer<?> getContainer() {
        return container;
    }
}
