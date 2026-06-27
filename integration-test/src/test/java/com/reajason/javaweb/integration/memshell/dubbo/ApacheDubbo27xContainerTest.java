package com.reajason.javaweb.integration.memshell.dubbo;

import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.stream.Stream;

@Testcontainers
@Tag("dubbo-container")
class ApacheDubbo27xContainerTest {

    private static final String IMAGE = "eclipse-temurin:17-jdk";

    private static final DubboProviderScenario APACHE_276 = apacheScenario(
            "apache-dubbo-2.7.6",
            "dubbo.apache276.provider.jar",
            20885,
            28086
    );
    private static final DubboProviderScenario APACHE_277 = apacheScenario(
            "apache-dubbo-2.7.7",
            "dubbo.apache277.provider.jar",
            20886,
            28088
    );
    private static final DubboProviderScenario APACHE_278 = apacheScenario(
            "apache-dubbo-2.7.8",
            "dubbo.apache278.provider.jar",
            20887,
            28090
    );
    private static final DubboProviderScenario APACHE_2723 = apacheScenario(
            "apache-dubbo-2.7.23",
            "dubbo.apache2723.provider.jar",
            20881,
            28082
    );

    @Container
    static final GenericContainer<?> apache276 = DubboContainerFactory.buildProvider(APACHE_276);
    @Container
    static final GenericContainer<?> apache277 = DubboContainerFactory.buildProvider(APACHE_277);
    @Container
    static final GenericContainer<?> apache278 = DubboContainerFactory.buildProvider(APACHE_278);
    @Container
    static final GenericContainer<?> apache2723 = DubboContainerFactory.buildProvider(APACHE_2723);

    static Stream<Arguments> scenarios() {
        return Stream.of(
                Arguments.of(apache276, APACHE_276),
                Arguments.of(apache277, APACHE_277),
                Arguments.of(apache278, APACHE_278),
                Arguments.of(apache2723, APACHE_2723)
        );
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("scenarios")
    void testDubboServiceRegistration(GenericContainer<?> container, DubboProviderScenario scenario) {
        DubboServiceAssertion.assertCommandService(container, scenario);
    }

    private static DubboProviderScenario apacheScenario(String name, String providerJarProperty, int dubboPort, int hessianPort) {
        return new DubboProviderScenario(
                name,
                "apache",
                providerJarProperty,
                IMAGE,
                dubboPort,
                Opcodes.V1_8,
                List.of(
                        new DubboProtocolTarget("dubbo", dubboPort),
                        new DubboProtocolTarget("hessian", hessianPort)
                )
        );
    }
}
