package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2025/9/19
 */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractContainerTest {
    private static final String NO_PROBE = "__NO_PROBE__";

    protected static Network newNetwork() {
        return Network.newNetwork();
    }

    protected static GenericContainer<?> buildPythonContainer(Network network) {
        return new GenericContainer<>(new ImageFromDockerfile()
                .withDockerfile(ContainerTool.neoGeorgDockerfile))
                .withNetwork(network);
    }

    protected static GenericContainer<?> buildContainer(ContainerTestConfig config, Network network) {
        GenericContainer<?> container = createContainer(config);
        if (config.getWarFile() != null && StringUtils.isNotBlank(config.getWarDeployPath())) {
            container.withCopyToContainer(config.getWarFile(), config.getWarDeployPath());
        }
        if(config.getJarFile() != null && StringUtils.isNotBlank(config.getJarDeployPath())){
            container.withCopyToContainer(config.getJarFile(), config.getJarDeployPath());
        }
        if (config.getJattachFile() != null) {
            container.withCopyToContainer(config.getJattachFile(), "/jattach");
        }
        if (config.getPidScript() != null) {
            container.withCopyToContainer(config.getPidScript(), "/fetch_pid.sh");
        }
        Map<String, String> env = config.getEnv();
        if (env != null) {
            env.forEach(container::withEnv);
        }
        if (network != null) {
            container.withNetwork(network);
            if (StringUtils.isNotBlank(config.getNetworkAlias())) {
                container.withNetworkAliases(config.getNetworkAlias());
            }
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

    protected static GenericContainer<?> buildContainer(ContainerTestConfig config) {
        return buildContainer(config, null);
    }

    protected abstract ContainerTestConfig getConfig();

    @AfterAll
    void tearDown() {
        GenericContainer<?> container = getContainer();
        if (container == null) {
            return;
        }
        long logDelayMillis = getConfig().getLogDelayMillis();
        if (logDelayMillis > 0) {
            try {
                Thread.sleep(logDelayMillis);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }
        String logs = container.getLogs();
        if (getConfig().isLogContainerOutput()) {
            log.info(logs);
        }
        if (getConfig().isAssertLogs()) {
            assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
        }
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        runShellInject(getConfig(), shellType, shellTool, packer);
    }

    @ParameterizedTest
    @MethodSource("probeShellTypesProvider")
    void testProbeInject(String shellType) {
        if (NO_PROBE.equals(shellType)) {
            Assumptions.assumeTrue(false, "No probe shell types configured.");
        }
        runProbeInject(getConfig(), shellType);
    }

    @ParameterizedTest
    @EnumSource(names = {"ClassLoaderJSP", "ClassLoaderJSPUnicode", "DefineClassJSP", "DefineClassJSPUnicode", "JSPX", "JSPXUnicode"})
    void testJspPackers(Packers packer) {
        ContainerTestConfig config = getConfig();
        if (config.isEnableJspPackerTest()) {
            String shellType = config.isJakarta() ? ShellType.JAKARTA_FILTER : ShellType.FILTER;
            String shellTool = ShellTool.Command;
            runShellInject(config, shellType, shellTool, packer);
        }
    }

    protected Stream<Arguments> casesProvider() {
        return generateTestCases(getConfig());
    }

    protected Stream<String> probeShellTypesProvider() {
        List<String> probeShellTypes = getConfig().getProbeShellTypes();
        if (probeShellTypes == null || probeShellTypes.isEmpty()) {
            return Stream.of(NO_PROBE);
        }
        return probeShellTypes.stream();
    }

    protected static Stream<Arguments> generateTestCases(ContainerTestConfig config) {
        if (config.getUnSupportedCases() != null || config.getUnSupportedShellTools() != null) {
            return TestCasesProvider.getTestCases(
                    config.getImageName(),
                    config.getServer(),
                    config.getSupportedShellTypes(),
                    config.getTestPackers(),
                    config.getUnSupportedCases(),
                    config.getUnSupportedShellTools());
        }
        return TestCasesProvider.getTestCases(
                config.getImageName(),
                config.getServer(),
                config.getSupportedShellTypes(),
                config.getTestPackers());
    }

    protected void runShellInject(ContainerTestConfig config, String shellType, String shellTool, Packers packer) {
        String url = getUrl();
        if (StringUtils.isNotBlank(config.getServerVersion())) {
            ShellAssertion.shellInjectIsOk(url, config.getServer(), config.getServerVersion(), shellType, shellTool,
                    config.getTargetJdkVersion(), packer, getContainer(), getPythonContainer());
        } else {
            ShellAssertion.shellInjectIsOk(url, config.getServer(), shellType, shellTool,
                    config.getTargetJdkVersion(), packer, getContainer(), getPythonContainer());
        }
    }

    protected void runProbeInject(ContainerTestConfig config, String shellType) {
        String url = getUrl();
        int probeTargetJdkVersion = config.getProbeTargetJdkVersion() == null
                ? config.getTargetJdkVersion()
                : config.getProbeTargetJdkVersion();
        if (StringUtils.isNotBlank(config.getServerVersion())) {
            ShellAssertion.testProbeInject(url, config.getServer(), config.getServerVersion(), shellType, probeTargetJdkVersion);
        } else {
            ShellAssertion.testProbeInject(url, config.getServer(), shellType, probeTargetJdkVersion);
        }
    }

    protected String getUrl() {
        GenericContainer<?> container = getContainer();
        ContainerTestConfig config = getConfig();
        String host = container.getHost();
        int port = container.getMappedPort(config.getExposedPort());
        String url = "http://" + host + ":" + port;
        String contextPath = config.getContextPath();
        if (StringUtils.isNotBlank(contextPath)) {
            if (!contextPath.startsWith("/")) {
                contextPath = "/" + contextPath;
            }
            url += contextPath;
        }
        log.info("container started, app url is : {}", url);
        return url;
    }

    protected GenericContainer<?> getContainer() {
        return getContainerField("container", true);
    }

    protected GenericContainer<?> getPythonContainer() {
        return getContainerField("python", false);
    }

    private static GenericContainer<?> createContainer(ContainerTestConfig config) {
        if (config.getDockerfilePath() != null) {
            return new GenericContainer<>(new ImageFromDockerfile()
                    .withDockerfile(config.getDockerfilePath()));
        }
        if (StringUtils.isBlank(config.getImageName())) {
            throw new IllegalArgumentException("imageName is required when dockerfilePath is not set.");
        }
        return new GenericContainer<>(config.getImageName());
    }

    private GenericContainer<?> getContainerField(String fieldName, boolean required) {
        Field field = findField(getClass(), fieldName);
        if (field == null) {
            if (required) {
                throw new IllegalStateException("Missing @" + fieldName + " container on " + getClass().getName());
            }
            return null;
        }
        try {
            field.setAccessible(true);
            Object value = field.get(Modifier.isStatic(field.getModifiers()) ? null : this);
            return (GenericContainer<?>) value;
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException("Unable to access " + fieldName + " on " + getClass().getName(), ex);
        }
    }

    private static Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}
