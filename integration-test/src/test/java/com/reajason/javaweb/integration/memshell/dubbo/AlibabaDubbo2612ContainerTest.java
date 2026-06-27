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
class AlibabaDubbo2612ContainerTest {

    private static final DubboProviderScenario SCENARIO = new DubboProviderScenario(
            "alibaba-dubbo-2.6.12",
            "alibaba",
            "dubbo.alibaba.provider.jar",
            "eclipse-temurin:8-jre",
            20880,
            Opcodes.V1_8,
            List.of(
                    new DubboProtocolTarget("dubbo", 20880),
                    new DubboProtocolTarget("hessian", 28080)
            )
    );

    @Container
    static final GenericContainer<?> container = DubboContainerFactory.buildProvider(SCENARIO);

    @Test
    void testDubboServiceRegistration() {
        DubboServiceAssertion.assertCommandService(container, SCENARIO);
    }
}
