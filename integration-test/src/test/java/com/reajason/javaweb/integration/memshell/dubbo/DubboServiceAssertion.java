package com.reajason.javaweb.integration.memshell.dubbo;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.Packers;
import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;

@Slf4j
final class DubboServiceAssertion {

    private static final String LOADER_INTERFACE = "io.github.reajason.dubbo.fixture.api.BytecodeLoadingService";
    private static final String COMMAND = "id";

    private DubboServiceAssertion() {
    }

    static void assertCommandService(GenericContainer<?> container, DubboProviderScenario scenario) {
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(
                scenario.shellType(),
                ShellTool.Command,
                Packers.Base64
        );
        MemShellResult result = ShellAssertion.generate(
                null,
                Server.Dubbo,
                null,
                scenario.shellType(),
                ShellTool.Command,
                scenario.targetJdkVersion(),
                shellToolConfig,
                Packers.Base64
        );
        String interfaceName = result.getInjectorConfig().getUrlPattern();
        String host = container.getHost();
        String loaderUrl = "dubbo://" + host + ":" + container.getMappedPort(scenario.loaderPort()) + "/" + LOADER_INTERFACE;

        log.info("loading {} into {} via {}", interfaceName, scenario.name(), loaderUrl);
        String loadOutput = DubboClientRunner.loadBytes(scenario.clientKind(), loaderUrl, result.getInjectorBytesBase64Str());
        log.info("{} load output: {}", scenario.name(), loadOutput);

        List<String> fallbackUrls = scenario.commandTargets().stream()
                .map(target -> target.url(host, container.getMappedPort(target.port()), interfaceName))
                .collect(Collectors.toList());
        List<String> commandUrls = DubboUrlResolver.resolveCommandUrls(loadOutput, interfaceName, fallbackUrls);

        for (String commandUrl : commandUrls) {
            String output = DubboClientRunner.runCommand(scenario.clientKind(), commandUrl, interfaceName, COMMAND);
            log.info("{} {} command output: {}", scenario.name(), DubboUrlResolver.protocolOf(commandUrl), output);
            assertThat(output, anyOf(containsString("uid="), containsString("injected-ok")));
        }
    }
}
