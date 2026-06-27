package com.reajason.javaweb.integration.memshell.dubbo;

import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

@Testcontainers
@Tag("dubbo-container")
class ApacheDubbo336ContainerTest {

    private static final DubboProviderScenario SCENARIO = new DubboProviderScenario(
            "apache-dubbo-3.3.6",
            "apache",
            "dubbo.apache336.provider.jar",
            "eclipse-temurin:17-jdk",
            20882,
            Opcodes.V1_8,
            List.of(
                    new DubboProtocolTarget("dubbo", 20882),
                    new DubboProtocolTarget("hessian", 28084),
                    new DubboProtocolTarget("tri", 50051)
            )
    );

    @Container
    static final GenericContainer<?> container = DubboContainerFactory.buildProvider(SCENARIO);

    @Test
    void testDubboServiceRegistration() {
        DubboServiceAssertion.assertCommandService(container, SCENARIO);
    }
}
