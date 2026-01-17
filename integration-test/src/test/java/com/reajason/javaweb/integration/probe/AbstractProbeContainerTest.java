package com.reajason.javaweb.integration.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.payload.FilterProbeFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Abstract base class for probe container tests.
 * Provides common test methods that are shared across all probe tests.
 *
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractProbeContainerTest {

    /**
     * Subclasses must provide their configuration.
     */
    protected abstract ProbeTestConfig getConfig();

    /**
     * Subclasses must provide their container instance.
     */
    protected abstract GenericContainer<?> getContainer();

    /**
     * Helper to build a container from config.
     */
    protected static GenericContainer<?> buildContainer(ProbeTestConfig config) {
        GenericContainer<?> container = new GenericContainer<>(config.getImageName());

        if (config.getWarFile() != null && StringUtils.isNotBlank(config.getWarDeployPath())) {
            container.withCopyToContainer(config.getWarFile(), config.getWarDeployPath());
        }

        if(config.getJarFile() != null && StringUtils.isNotBlank(config.getJarDeployPath())){
            container.withCopyFileToContainer(config.getJarFile(), config.getJarDeployPath());
        }

        if (config.getWaitStrategy() != null) {
            container.waitingFor(config.getWaitStrategy());
        } else if (StringUtils.isNotBlank(config.getHealthCheckPath())) {
            container.waitingFor(Wait.forHttp(config.getHealthCheckPath()));
        }

        container.withExposedPorts(config.getExposedPort());

        if (config.isPrivilegedMode()) {
            container.withPrivilegedMode(true);
        }
        if(config.getCommand() != null){
            container.withCommand(config.getCommand());
        }

        return container;
    }

    /**
     * Get the URL based on the configured strategy.
     */
    protected String getUrl() {
        GenericContainer<?> container = getContainer();
        ProbeTestConfig config = getConfig();
        int port = container.getMappedPort(config.getExposedPort());
        String host = container.getHost();

        String url = "http://" + host + ":" + port;
        String contextPath = config.getContextPath();
        if (StringUtils.isNotBlank(contextPath)) {
            if (!contextPath.startsWith("/")) {
                contextPath = "/" + contextPath;
            }
            url += contextPath;
        }

        log.info("container started, app url is: {}", url);
        return url;
    }

    @AfterAll
    void tearDown() {
        GenericContainer<?> container = getContainer();
        if (container != null) {
            log.info(container.getLogs());
        }
    }

    // ==================== Test Methods ====================

    @Test
    protected void testJDK() {
        doTestJDK();
    }

    /**
     * Subclasses can override testJDK() with @RetryingTest(3) and call this method.
     */
    protected void doTestJDK() {
        String url = getUrl();
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals(getConfig().getExpectedJdkVersion(), data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrl();
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(
                Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"),
                data);
    }

    @Test
    void testServerDetection() {
        String url = getUrl();
        String data = VulTool.post(url + "/b64", DetectionTool.getServerDetection());
        assertEquals(getConfig().getServer(), data);
    }

    @Test
    @SneakyThrows
    protected void testCommandReqHeaderResponseBody() {
        Assumptions.assumeTrue(getConfig().isSupportsCommand(),
                "Command test not supported for this server");
        String url = getUrl();
        ProbeAssertion.responseCommandIsOk(url, getConfig().getServer(), getConfig().getTargetJdkVersion());
    }

    @Test
    @SneakyThrows
    protected void testScriptEngineReqHeaderResponseBody() {
        Assumptions.assumeTrue(getConfig().isSupportsScriptEngine(),
                "ScriptEngine test not supported for this server");
        String url = getUrl();
        ProbeAssertion.responseScriptEngineIsOk(url, getConfig().getServer(), getConfig().getTargetJdkVersion());
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        Assumptions.assumeTrue(getConfig().isSupportsBytecode(),
                "Bytecode test not supported for this server");
        String url = getUrl();
        ProbeAssertion.responseBytecodeIsOk(url, getConfig().getServer(), getConfig().getTargetJdkVersion());
        if (getConfig().isSupportsBytecodeWithoutPrefix()) {
            ProbeAssertion.responseBytecodeWithoutPrefixIsOk(url, getConfig().getServer(), getConfig().getTargetJdkVersion());
        }
    }

    @Test
    void testFilterProbe() {
        Assumptions.assumeTrue(getConfig().isSupportsFilterProbe(),
                "Filter probe test not supported for this server");
        String url = getUrl();
        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(getConfig().getServer()));
        ShellAssertion.assertFilterProbeIsRight(data);
    }

    @Test
    protected void testFilterFirstInject() {
        Assumptions.assumeTrue(getConfig().isSupportsFilterProbe(),
                "Filter first inject test not supported for this server");
        String url = getUrl();
        ProbeTestConfig config = getConfig();

        String shellType = config.isJakarta() ? ShellType.JAKARTA_FILTER : ShellType.FILTER;
        MemShellResult memShellResult = shellInjectIsOk(
                url,
                config.getServer(),
                shellType,
                ShellTool.Command,
                getConfig().getTargetJdkVersion(),
                Packers.BigInteger,
                getContainer());

        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(config.getServer()));
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertEquals(filterName, memShellResult.getShellClassName());
    }

    @Test
    @SneakyThrows
    protected void testCommandReqHeaderResponseBodySpring() {
        Assumptions.assumeTrue(getConfig().isSupportsSpringWebMvc(),
                "Spring WebMVC test not supported for this server");
        String url = getUrl();
        ProbeAssertion.responseCommandIsOk(url, Server.SpringWebMvc, getConfig().getTargetJdkVersion());
    }
}
