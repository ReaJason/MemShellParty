package com.reajason.javaweb.integration.probe.payara;

import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.payload.FilterProbeFactory;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class Payara620222ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.payaraJakarta(
                    "reajason/payara:6.2022.2-jdk11",
                    "/usr/local/payara6/glassfish/domains/domain1/autodeploy/app.war")
            .expectedJdkVersion("JDK|11.0.25|55")
            .targetJdkVersion(Opcodes.V11)
            .waitStrategy(Wait.forLogMessage(".*JMXService.*", 1))
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

    @Test
    protected void testFilterFirstInject() {
        String url = getUrl();
        String shellType = getConfig().isJakarta() ? ShellType.JAKARTA_FILTER : ShellType.FILTER;
        MemShellResult memShellResult = shellInjectIsOk(
                url,
                getConfig().getServer(),
                shellType,
                ShellTool.Command,
                Opcodes.V11,
                Packers.BigInteger,
                getContainer());

        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(getConfig().getServer()));
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertEquals(filterName, memShellResult.getShellClassName());
    }
}
