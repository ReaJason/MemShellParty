package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.woodpecker.WoodpeckerStubs.ArgsUsageBinder;
import com.reajason.javaweb.woodpecker.WoodpeckerStubs.HelperPluginCallbacks;
import com.reajason.javaweb.woodpecker.WoodpeckerStubs.PluginManagerCallbacks;
import com.reajason.javaweb.woodpecker.WoodpeckerStubs.ResultOutput;
import me.gv7.woodpecker.plugin.IHelper;
import me.gv7.woodpecker.plugin.IHelperPlugin;
import me.gv7.woodpecker.plugin.IPluginManager;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 按框架的加载顺序驱动插件：反射拿入口类 → registerPluginManagerCallbacks → HelperPluginMain
 * → 用参数表格默认值调 doHelp → 断言输出。跑通即说明插件在 Woodpecker 里可用。
 */
class WoodpeckerPluginSmokeTest {

    @Test
    void frameworkLoadsPluginAndRegistersThreeTabs() throws Throwable {
        HelperPluginCallbacks callbacks = loadPlugin();

        assertEquals("MemShellParty", callbacks.getName());
        assertEquals("ReaJason", callbacks.getAuthor());
        assertNotNull(callbacks.getDescription());
        assertEquals(Arrays.asList("内存马生成", "探测马生成", "使用帮助"), callbacks.captions());
        // 版本取自 SDK 的 version.properties，构建产物里应当是项目版本而不是 dev
        assertFalse(callbacks.getVersion() == null || callbacks.getVersion().trim().isEmpty());
    }

    @Test
    void everyTabDeclaresArgsWithNamesAndDescriptions() throws Throwable {
        HelperPluginCallbacks callbacks = loadPlugin();
        for (IHelper helper : callbacks.getHelpers()) {
            ArgsUsageBinder binder = (ArgsUsageBinder) helper.getHelperCutomArgs();
            assertFalse(binder.getArgsList().isEmpty(), helper.getHelperTabCaption() + " 没有参数");
            assertNotNull(binder.getUsage(), helper.getHelperTabCaption() + " 没有使用说明");
            // 框架界面里真正能填参数的地方是 Args 文本框（参数名=值 一行一个），说明里必须点出来
            assertTrue(binder.getUsage().contains("Generate"),
                    helper.getHelperTabCaption() + " 的使用说明没写怎么执行：" + binder.getUsage());
            for (WoodpeckerStubs.Arg arg : binderArgs(binder)) {
                assertNotNull(arg.getName(), helper.getHelperTabCaption() + " 参数名为空");
                assertNotNull(arg.getDescription(), arg.getName() + " 没有说明");
                assertEquals(me.gv7.woodpecker.plugin.IArg.ARG_TYPE_STRING, arg.getType(),
                        arg.getName() + " 应为文本类型（表格里按文本编辑，插件自己解析）");
            }
        }
    }

    @Test
    void defaultArgsGenerateAMemshellWhosePayloadIsAClass() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        ResultOutput output = run(helper, null);

        assertTrue(output.hasLineContaining("服务端: Tomcat"), output.text());
        assertTrue(output.hasLineContaining("工具 / 类型: Godzilla / Listener"), output.text());
        assertTrue(output.hasLineContaining("密码:"), output.text());
        assertTrue(output.hasLineContaining("密钥:"), output.text());
        assertTrue(output.hasLineContaining("内存马类名:"), output.text());
        assertTrue(output.hasLineContaining("生成完成"), output.text());

        // 默认 DefaultBase64 打包的是注入器类字节：解码后应当是 class 文件魔数
        byte[] payload = Base64.getDecoder().decode(singlePayload(output));
        assertEquals((byte) 0xCA, payload[0]);
        assertEquals((byte) 0xFE, payload[1]);
        assertEquals((byte) 0xBA, payload[2]);
        assertEquals((byte) 0xBE, payload[3]);
    }

    @Test
    void explicitArgsDriveTheRequest() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("server", "Tomcat");
        args.put("shellTool", "Behinder");
        args.put("shellType", "Filter");
        args.put("packingMethod", "GzipBase64");
        args.put("urlPattern", "/api/*");
        args.put("pass", "abc123");
        args.put("debug", "true");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("工具 / 类型: Behinder / Filter"), output.text());
        assertTrue(output.hasLineContaining("打包方式: GzipBase64"), output.text());
        assertTrue(output.hasLineContaining("挂载地址: /api/*"), output.text());
        assertTrue(output.hasLineContaining("密码: abc123"), output.text());
        assertFalse(output.rawLines().isEmpty(), "没有输出打包产物");
    }

    @Test
    void aggregatePackerPrintsEveryVariant() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("packingMethod", "JSP");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("打包结果（JSP，共"), output.text());
        assertTrue(output.text().contains("### ClassLoaderJSP"), output.text());
        assertTrue(output.text().contains("### DefineClassJSP"), output.text());
    }

    @Test
    void unsupportedServerAndMissingCustomClassReportFieldErrors() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");

        Map<String, Object> badServer = new LinkedHashMap<String, Object>();
        badServer.put("server", "NotAServer");
        ResultOutput output = run(helper, badServer);
        assertTrue(output.hasLineContaining("不支持的 server: NotAServer"), output.text());
        assertTrue(output.hasLineContaining("Undertow"), "错误里应列出可选值：" + output.text());

        Map<String, Object> custom = new LinkedHashMap<String, Object>();
        custom.put("shellTool", "Custom");
        ResultOutput customOutput = run(helper, custom);
        assertTrue(customOutput.hasLineContaining("shellClassBase64"), customOutput.text());
    }

    @Test
    void servletShellTypeRequiresConcreteUrlPattern() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("server", "Tomcat");
        args.put("shellTool", "Command");
        args.put("shellType", "Servlet");
        args.put("urlPattern", "/*");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("urlPattern"), output.text());
    }

    @Test
    void probeResponseHeaderMethodPrintsHeaderName() throws Throwable {
        IHelper helper = loadPlugin().helper("探测马生成");

        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("probeMethod", "ResponseHeader");
        args.put("probeContent", "Command");
        args.put("server", "Tomcat");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("探测方式: ResponseHeader / Command"), output.text());
        assertTrue(output.hasLineContaining("响应头名称: X-"), output.text());
        assertFalse(output.rawLines().isEmpty(), "没有输出打包产物");
    }

    @Test
    void probeLooksUpHostAndSleepArguments() throws Throwable {
        IHelper helper = loadPlugin().helper("探测马生成");

        Map<String, Object> responseBody = new LinkedHashMap<String, Object>();
        responseBody.put("probeMethod", "ResponseBody");
        ResultOutput responseOutput = run(helper, responseBody);
        assertTrue(responseOutput.hasLineContaining("探测方式: ResponseBody"), responseOutput.text());
        assertTrue(responseOutput.hasLineContaining("回显参数名:"), responseOutput.text());
        assertTrue(responseOutput.hasLineContaining("探测马类名:"), responseOutput.text());
        assertFalse(responseOutput.rawLines().isEmpty(), "没有输出打包产物");

        Map<String, Object> dnsLog = new LinkedHashMap<String, Object>();
        dnsLog.put("probeMethod", "DNSLog");
        dnsLog.put("probeContent", "JDK");
        ResultOutput missingHost = run(helper, dnsLog);
        assertTrue(missingHost.hasLineContaining("DNSLog 域名"), missingHost.text());

        dnsLog.put("host", "abc.dnslog.cn");
        ResultOutput dnsOutput = run(helper, dnsLog);
        assertTrue(dnsOutput.hasLineContaining("DNSLog 域名: abc.dnslog.cn"), dnsOutput.text());

        Map<String, Object> sleep = new LinkedHashMap<String, Object>();
        sleep.put("probeMethod", "Sleep");
        sleep.put("sleepServer", "Tomcat");
        sleep.put("seconds", "7");
        ResultOutput sleepOutput = run(helper, sleep);
        assertTrue(sleepOutput.hasLineContaining("休眠服务: Tomcat，秒数: 7"), sleepOutput.text());
    }

    @Test
    void catalogListsServersPackersAndProbeOptions() throws Throwable {
        IHelper helper = loadPlugin().helper("使用帮助");
        ResultOutput output = run(helper, null);

        assertTrue(output.text().contains("Tomcat："), output.text());
        assertTrue(output.text().contains("Undertow："), output.text());
        assertTrue(output.text().contains("DefaultBase64"), output.text());
        assertTrue(output.text().contains("ResponseBody → Command"), output.text());
        assertTrue(output.text().contains("sleepServer"), output.text());
        assertTrue(output.hasLineContaining("add-opens"), output.text());
    }

    @Test
    void catalogKeywordFiltersTheListing() throws Throwable {
        IHelper helper = loadPlugin().helper("使用帮助");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("keyword", "Jetty");
        ResultOutput output = run(helper, args);

        assertTrue(output.text().contains("Jetty："), output.text());
        assertFalse(output.text().contains("Undertow："), output.text());
    }

    /**
     * 参数名只写在两个生成页签里，使用帮助是用户查名字的地方 —— 少列一个名字，用户就填不出这个参数。
     */
    @Test
    void catalogListsEveryArgNameOfBothTabs() throws Throwable {
        HelperPluginCallbacks callbacks = loadPlugin();
        ResultOutput catalog = run(callbacks.helper("使用帮助"), null);

        for (String tab : Arrays.asList("内存马生成", "探测马生成")) {
            for (WoodpeckerStubs.Arg arg : binderArgs((ArgsUsageBinder) callbacks.helper(tab).getHelperCutomArgs())) {
                assertTrue(catalog.text().contains(arg.getName()),
                        "「使用帮助」里没有列出 " + tab + " 的参数 " + arg.getName() + "：" + catalog.text());
            }
        }
    }

    /**
     * Args 文本框的预填内容（默认值非空的参数）：用户打开页签第一眼看到的就是这些，
     * 改这里等于改界面首屏，顺序也要跟着改。
     */
    @Test
    void argsBoxPrefillsTheCommonArguments() throws Throwable {
        HelperPluginCallbacks callbacks = loadPlugin();

        assertEquals(Arrays.asList(
                        "server=Tomcat",
                        "shellTool=Godzilla",
                        "shellType=Listener",
                        "byPassJavaModule=false",
                        "shrink=true",
                        "staticInitialize=true",
                        "lambdaSuffix=false",
                        "packingMethod=DefaultBase64"),
                prefillLines(callbacks.helper("内存马生成")));
        assertEquals(Arrays.asList(
                        "probeMethod=ResponseBody",
                        "byPassJavaModule=false",
                        "shrink=true",
                        "staticInitialize=true",
                        "lambdaSuffix=false",
                        "packingMethod=DefaultBase64"),
                prefillLines(callbacks.helper("探测马生成")));
    }

    /**
     * 预填的 shellType 换了服务端就失效：桌面端表单此时会自动回落到首个可用类型，
     * 插件也回落并提示，而不是让用户去删掉那一行。
     */
    @Test
    void linkedShellTypeFallsBackWhenTheServerChanges() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("server", "SpringWebFlux");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("shellType=Listener 不适用于 SpringWebFlux"), output.text());
        assertTrue(output.hasLineContaining("已改用"), output.text());
        assertFalse(output.hasLineContaining("不支持的 shellType"), output.text());
        assertTrue(output.hasLineContaining("生成完成"), output.text());
    }

    /**
     * 类型名本身写错（哪个服务端都没有）不是回落，仍要报错并列出可选值。
     */
    @Test
    void unknownShellTypeStillReportsAnError() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("shellType", "Listener2");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("不支持的 shellType: Listener2"), output.text());
        assertTrue(output.hasLineContaining("Valve"), "错误里应列出可选值：" + output.text());
    }

    /**
     * 布尔参数写错只提示不报错，按预填的默认值继续生成。
     */
    @Test
    void unrecognizedBooleanValueWarnsAndKeepsGoing() throws Throwable {
        IHelper helper = loadPlugin().helper("内存马生成");
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("shrink", "ture");
        ResultOutput output = run(helper, args);

        assertTrue(output.hasLineContaining("布尔参数 shrink 的值「ture」无法识别"), output.text());
        assertTrue(output.hasLineContaining("按 true 处理"), output.text());
        assertTrue(output.hasLineContaining("生成完成"), output.text());
    }

    /**
     * 框架的加载顺序：反射实例化入口类 → 登记辅助插件 → 调用 HelperPluginMain。
     */
    private static HelperPluginCallbacks loadPlugin() throws Throwable {
        Class<?> entry = Class.forName("me.gv7.woodpecker.plugin.WoodpeckerPluginManager");
        IPluginManager pluginManager = (IPluginManager) entry.getDeclaredConstructor().newInstance();

        PluginManagerCallbacks managerCallbacks = new PluginManagerCallbacks();
        pluginManager.registerPluginManagerCallbacks(managerCallbacks);
        assertEquals(1, managerCallbacks.getHelperPlugins().size(), "没有登记辅助插件");

        HelperPluginCallbacks callbacks = new HelperPluginCallbacks();
        managerCallbacks.getHelperPlugins().get(0).HelperPluginMain(callbacks);
        return callbacks;
    }

    /**
     * 用参数表格默认值执行，再用 {@code overrides} 覆盖指定参数（null 表示全部用默认值）。
     */
    private static ResultOutput run(IHelper helper, Map<String, Object> overrides) throws Throwable {
        ArgsUsageBinder binder = (ArgsUsageBinder) helper.getHelperCutomArgs();
        Map<String, Object> args = binder.defaultArgs();
        if (overrides != null) {
            args.putAll(overrides);
        }
        ResultOutput output = new ResultOutput();
        helper.doHelp(args, output);
        assertFalse(output.getLines().isEmpty(), helper.getHelperTabCaption() + " 没有任何输出");
        return output;
    }

    /**
     * @return 单条目打包产物（默认 DefaultBase64 只有一条）
     */
    private static String singlePayload(ResultOutput output) {
        List<String> raw = output.rawLines();
        assertFalse(raw.isEmpty(), "输出里没有打包产物：" + output.text());
        return raw.get(raw.size() - 1);
    }

    private static List<WoodpeckerStubs.Arg> binderArgs(ArgsUsageBinder binder) {
        List<WoodpeckerStubs.Arg> args = new java.util.ArrayList<WoodpeckerStubs.Arg>();
        for (me.gv7.woodpecker.plugin.IArg arg : binder.getArgsList()) {
            args.add((WoodpeckerStubs.Arg) arg);
        }
        return args;
    }

    /**
     * @return 界面上 Args 文本框里一行的样子（{@code 参数名=默认值}），按声明顺序
     */
    private static List<String> prefillLines(IHelper helper) throws Throwable {
        ArgsUsageBinder binder = (ArgsUsageBinder) helper.getHelperCutomArgs();
        List<String> lines = new ArrayList<String>();
        for (Map.Entry<String, Object> entry : binder.prefilledArgs().entrySet()) {
            lines.add(entry.getKey() + "=" + entry.getValue());
        }
        return lines;
    }
}
