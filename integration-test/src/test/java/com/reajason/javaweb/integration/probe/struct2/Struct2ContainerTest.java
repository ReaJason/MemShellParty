package com.reajason.javaweb.integration.probe.struct2;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.reajason.javaweb.integration.ContainerTool.struct2WarFile;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Testcontainers
public class Struct2ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.tomcat("tomcat:8-jre8")
            .warFile(struct2WarFile)
            .expectedJdkVersion("JRE|1.8.0_402|52")
            .targetJdkVersion(Opcodes.V1_8)
            .supportsBytecode(false)
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
    @Test
    @SneakyThrows
    protected void testCommandReqHeaderResponseBody() {
        String url = getUrl();
        ProbeAssertion.responseCommandIsOk(url, Server.Struct2, Opcodes.V1_8);
    }

    @Override
    @Test
    @SneakyThrows
    protected void testScriptEngineReqHeaderResponseBody() {
        String url = getUrl();
        ProbeAssertion.responseScriptEngineIsOk(url, Server.Struct2, Opcodes.V1_8);
    }
}
