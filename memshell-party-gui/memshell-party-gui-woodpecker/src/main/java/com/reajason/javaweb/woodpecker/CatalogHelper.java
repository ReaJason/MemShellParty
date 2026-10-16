package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeConfigCatalogService;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.packer.PackerCategory;
import me.gv7.woodpecker.plugin.IArg;
import me.gv7.woodpecker.plugin.IArgsUsageBinder;
import me.gv7.woodpecker.plugin.IHelper;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IResultOutput;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 「使用帮助」页签：参数表格没有下拉框（Woodpecker 的参数表单就是一张文本表格），
 * 可选值只能靠这一页列出来 —— 目录直接取自生成引擎注册表，与桌面端/Web 端同源。
 */
public class CatalogHelper implements IHelper {

    private final IPluginHelper pluginHelper;

    public CatalogHelper(IPluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Override
    public String getHelperTabCaption() {
        return "使用帮助";
    }

    @Override
    public IArgsUsageBinder getHelperCutomArgs() {
        List<IArg> args = new ArrayList<IArg>();
        args.add(Args.arg(pluginHelper, "keyword", "",
                "可选：只看包含该关键字的条目（如 Tomcat、JSP、Command），留空看全部"));
        return Args.binder(pluginHelper, args,
                "点 Generate 列出服务端/工具/类型/打包方式/探测方式等全部可选值；填 keyword 只看含该关键字的条目。");
    }

    @Override
    public void doHelp(Map<String, Object> customArgs, final IResultOutput resultOutput) {
        PluginRuntime.run(resultOutput, new PluginRuntime.Task() {
            @Override
            public void run(IResultOutput output) {
                print(customArgs, output);
            }
        });
    }

    private void print(Map<String, Object> args, IResultOutput output) {
        String keyword = Args.str(args, "keyword", "");
        if (!keyword.isEmpty()) {
            output.infoPrintln("关键字过滤：" + keyword);
        }
        output.infoPrintln("用法：切到「内存马生成」/「探测马生成」，在 Args 文本框里按「参数名=值」一行一个填参数"
                + "（如 shellType=Filter、pass=abc123），常用参数已按默认值预填，点 Generate 执行，"
                + "结果输出在下方 Result；没填的参数由生成器自动决定或随机（随机出来的密码/密钥/类名会打印在结果里）。"
                + "点参数区右上角「?」可查看该页签的全部参数与说明。");
        output.infoPrintln("生成结果仅用于已获授权的安全测试。");
        output.rawPrintln("");

        ConfigCatalogService configCatalogService = new ConfigCatalogService();
        ConfigCatalogService.ConfigCatalog catalog = configCatalogService.load();
        ProbeConfigCatalogService probeCatalog = new ProbeConfigCatalogService(configCatalogService);

        printColumn(output, "服务端 / 工具 / 挂载类型（server / shellTool / shellType）", keyword);
        boolean matched = false;
        // 这一页要把整张矩阵逐行摊开，所以取原始表；按轴查询才走 ShellTypeCatalog 的 getShellTools/getShellTypes
        for (Map.Entry<String, Map<String, List<String>>> server
                : catalog.getShellTypeCatalog().asMap().entrySet()) {
            List<String> customTypes = catalog.getCustomShellTypes().get(server.getKey());
            String line = server.getKey() + "：";
            if (customTypes != null && !customTypes.isEmpty() && !"Custom".equals(server.getKey())) {
                line = line + "Custom[" + String.join(", ", customTypes) + "]，";
            }
            List<String> toolParts = new ArrayList<String>();
            for (Map.Entry<String, List<String>> tool : server.getValue().entrySet()) {
                toolParts.add(tool.getKey() + "[" + String.join(", ", tool.getValue()) + "]");
            }
            line = line + String.join("，", toolParts);
            if (matches(keyword, server.getKey(), line)) {
                output.rawPrintln(line);
                matched = true;
            }
        }
        if (!matched && !keyword.isEmpty()) {
            output.rawPrintln("（没有匹配的服务端/工具/类型）");
        }

        printColumn(output, "打包方式（packingMethod）", keyword);
        matched = false;
        for (PackerCategory category : catalog.getPackers()) {
            String line = category.getName();
            if (category.hasChildren()) {
                line = line + "：" + String.join(", ", category.getChildren());
            }
            if (matches(keyword, category.getName(), line)) {
                output.rawPrintln(line);
                matched = true;
            }
        }
        if (!matched && !keyword.isEmpty()) {
            output.rawPrintln("（没有匹配的打包方式）");
        }

        printColumn(output, "探测马（probeMethod / probeContent / server）", keyword);
        output.rawPrintln("探测方式：");
        for (String method : probeCatalog.getProbeMethods()) {
            output.rawPrintln("  " + method + " → " + String.join(", ", probeCatalog.getProbeContents(method)));
        }
        output.rawPrintln("ResponseBody 支持的服务端：" + String.join(", ", probeCatalog.getResponseBodyServers()));
        output.rawPrintln("Sleep 支持的服务端：" + String.join(", ", probeCatalog.getSleepServers()));
        output.rawPrintln("探测马可用打包方式："
                + String.join(", ", packerNames(probeCatalog.getPackers())));

        printColumn(output, "参数名（Args 文本框里按 参数名=值 一行一个填）", keyword);
        output.rawPrintln("内存马参数：server、serverVersion、shellTool、shellType、packingMethod、targetJdkVersion、"
                + "urlPattern、shellClassName、injectorClassName、pass、key、paramName、template、headerName、headerValue、"
                + "encryptor、implementationClass、shellClassBase64、shrink、staticInitialize、byPassJavaModule、"
                + "lambdaSuffix、debug");
        output.rawPrintln("探测马参数：probeMethod、probeContent、packingMethod、server、host、seconds、sleepServer、"
                + "reqParamName、commandTemplate、shellClassName、targetJdkVersion、shrink、staticInitialize、"
                + "byPassJavaModule、lambdaSuffix、debug");

        printColumn(output, "工具参数（按 shellTool 取用，参数名与 web 端 /api/config/shelltool/configs 同源）", keyword);
        for (ToolConfigFactory.ToolConfigDescriptor descriptor : catalog.getShellToolConfigs()) {
            List<ToolConfigFactory.ConfigParam> params = descriptor.getParams();
            if (params.isEmpty()) {
                continue;
            }
            List<String> parts = new ArrayList<String>();
            for (ToolConfigFactory.ConfigParam param : params) {
                String part = param.getOptions().isEmpty()
                        ? param.getName() + "(文本)"
                        : param.getName() + "[" + String.join(", ", param.getOptions()) + "]";
                if (param.getGroup() == ConfigField.Group.ADVANCED) {
                    part = part + "(高级)";
                }
                parts.add(part);
            }
            String tool = descriptor.getTool();
            String line = tool + "：" + String.join("，", parts);
            if (matches(keyword, tool, line)) {
                output.rawPrintln(line);
            }
        }

        printColumn(output, "其它", keyword);
        output.rawPrintln("目标 JRE 版本 targetJdkVersion：50 Java 6 / 52 Java 8 / 53 Java 9 / 55 Java 11 / 61 Java 17 / 65 Java 21");
        output.rawPrintln("服务版本 serverVersion：TongWeb 6、7、8；Jetty 6、7+、12；其余不区分版本");
        output.rawPrintln("布尔参数（shrink / staticInitialize / byPassJavaModule / lambdaSuffix / debug）："
                + "填 true/false、1/0、yes/no、on/off 均可，留空即默认");
        output.rawPrintln("");
        output.rawPrintln("提示一：JDK 9+ 上框架自身启动就需要 --add-exports java.desktop/com.apple.eawt=ALL-UNNAMED"
                + "（macOS，否则报 IllegalAccessError: com.apple.eawt.Application），"
                + "JDK 26 上还应加 --enable-native-access=ALL-UNNAMED 消掉 SQLite 的原生访问警告：");
        output.rawPrintln("  java --add-exports java.desktop/com.apple.eawt=ALL-UNNAMED \\");
        output.rawPrintln("       --enable-native-access=ALL-UNNAMED \\");
        output.rawPrintln("       -jar woodpecker-framework.jar");
        output.rawPrintln("提示二：部分打包方式（JavaDeserialize 系列反序列化 gadget 等）会用到 JDK 内部 API，"
                + "若生成时报 IllegalAccessError（TemplateUtils cannot access ... com.sun.org.apache.xalan...），"
                + "在启动参数里补上下面几项即可：");
        output.rawPrintln("  java --add-exports java.desktop/com.apple.eawt=ALL-UNNAMED \\");
        output.rawPrintln("       --enable-native-access=ALL-UNNAMED \\");
        output.rawPrintln("       --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \\");
        output.rawPrintln("       --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \\");
        output.rawPrintln("       --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \\");
        output.rawPrintln("       --add-opens java.base/java.util=ALL-UNNAMED \\");
        output.rawPrintln("       --add-opens java.base/java.lang=ALL-UNNAMED \\");
        output.rawPrintln("       -jar woodpecker-framework.jar");
    }

    private static void printColumn(IResultOutput output, String title, String keyword) {
        output.rawPrintln("");
        output.infoPrintln("==== " + title + (keyword.isEmpty() ? "" : "（含关键字 " + keyword + "）") + " ====");
    }

    private static boolean matches(String keyword, String name, String line) {
        if (keyword.isEmpty()) {
            return true;
        }
        String lower = keyword.toLowerCase(java.util.Locale.ROOT);
        return name.toLowerCase(java.util.Locale.ROOT).contains(lower)
                || line.toLowerCase(java.util.Locale.ROOT).contains(lower);
    }

    private static List<String> packerNames(List<PackerCategory> categories) {
        List<String> names = new ArrayList<String>();
        for (PackerCategory category : categories) {
            names.add(category.getName());
            names.addAll(category.getChildren());
        }
        return names;
    }
}
