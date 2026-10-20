package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.packer.Packers;
import me.gv7.woodpecker.plugin.IArg;
import me.gv7.woodpecker.plugin.IArgsUsageBinder;
import me.gv7.woodpecker.plugin.IHelper;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IResultOutput;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 「内存马生成」页签：参数表格决定服务端/工具/类型/打包方式，执行后输出打包好的 payload。
 *
 * <p>取值与联动全部交给 GUI SDK 的 {@code MemShellFormController}（与桌面端表单同一份规则：
 * 服务端决定候选工具、工具决定候选类型、类型决定候选打包方式，非法组合自动回落到首个可用项），
 * 生成也走同一个 {@code GenerationService} —— 插件里没有第二套生成逻辑。
 */
public class MemShellHelper implements IHelper {

    private final IPluginHelper pluginHelper;

    public MemShellHelper(IPluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Override
    public String getHelperTabCaption() {
        return "内存马生成";
    }

    @Override
    public IArgsUsageBinder getHelperCutomArgs() {
        // 声明顺序 = Args 文本框里的预填顺序：常用参数在前（给默认值即预填），其余留空表示自动/随机
        List<IArg> args = new ArrayList<IArg>();
        args.add(Args.arg(pluginHelper, "server", "Tomcat",
                "目标中间件，如 Tomcat / Jetty / Undertow / WebLogic / SpringWebMVC / Dubbo（全部可选值见「使用帮助」）"));
        args.add(Args.arg(pluginHelper, "shellTool", "Godzilla",
                "内存马工具，如 Godzilla / Behinder / Command / Suo5 / AntSword / Custom（见「使用帮助」）"));
        args.add(Args.arg(pluginHelper, "shellType", "Listener",
                "挂载类型，如 Listener / Filter / Servlet / Valve / Handler；换服务端或工具后若该类型不可用会自动回落到首个可用类型"));
        args.add(Args.arg(pluginHelper, "byPassJavaModule", "false",
                "移除 JDK9+ 模块限制，true/false；目标 JDK 为 9+ 时自动生效，填 true 可强制开启"));
        args.add(Args.arg(pluginHelper, "shrink", "true", "精简生成字节码，true/false"));
        args.add(Args.arg(pluginHelper, "staticInitialize", "true", "追加静态代码块初始化，true/false"));
        args.add(Args.arg(pluginHelper, "lambdaSuffix", "false", "类名追加 lambda 风格后缀，true/false"));
        args.add(Args.arg(pluginHelper, "packingMethod", Packers.DefaultBase64,
                "打包方式，如 DefaultBase64 / GzipBase64 / JSP / JSPX / BCEL / ScriptEngine（见「使用帮助」）"));

        args.add(Args.arg(pluginHelper, "serverVersion", "",
                "服务版本，留空自动；TongWeb（6/7/8）与 Jetty（6/7+/12）的部分类型必须指定"));
        args.add(Args.arg(pluginHelper, "targetJdkVersion", "",
                "目标 JRE 版本 50/52/53/55/61/65，留空自动（SpringWebFlux、XXLJOB、Dubbo 自动 Java 8）"));
        args.add(Args.arg(pluginHelper, "urlPattern", "",
                "挂载路径，留空默认 /*；Servlet/Handler/WebSocket 等类型必须给具体路径"));
        args.add(Args.arg(pluginHelper, "shellClassName", "",
                "内存马类名，留空随机（LambdaSuffix 会追加后缀）"));
        args.add(Args.arg(pluginHelper, "injectorClassName", "",
                "注入器类名，留空随机"));
        args.add(Args.arg(pluginHelper, "pass", "",
                "连接密码（Godzilla / Behinder / AntSword 共用），留空随机（结果里会打印实际取值）"));
        args.add(Args.arg(pluginHelper, "key", "",
                "Godzilla 密钥，留空随机"));
        args.add(Args.arg(pluginHelper, "paramName", "",
                "Command 参数名，留空随机"));
        args.add(Args.arg(pluginHelper, "template", "",
                "Command 命令模板，{command} 为命令占位符"));
        args.add(Args.arg(pluginHelper, "headerName", "",
                "Header 型工具的请求头名，留空取该工具默认（多数 User-Agent，NeoreGeorg 为 Referer）"));
        args.add(Args.arg(pluginHelper, "headerValue", "",
                "Header 型工具的请求头值，留空随机"));
        args.add(Args.arg(pluginHelper, "encryptor", "",
                "Command 加密器（如 Base64 / AES / XOR），留空取工具默认"));
        args.add(Args.arg(pluginHelper, "implementationClass", "",
                "Command 执行实现类，留空取工具默认"));
        args.add(Args.arg(pluginHelper, "shellClassBase64", "",
                "Custom 工具的自定义内存马类（Base64），缺省走内置模板"));
        args.add(Args.arg(pluginHelper, "debug", "",
                "目标服务端打印调试日志，true/false，留空默认关"));
        return Args.binder(pluginHelper, args,
                "Args 文本框里一行一个「参数名=值」（如 shellType=Filter、pass=abc123），只写要改的；"
                        + "上面已按默认值预填常用参数，点 Generate 执行，结果在下方 Result。"
                        + "没填的参数由生成器自动决定或随机，实际取值会打印在结果里；"
                        + "「?」可查看全部参数与说明，可选参数：serverVersion、targetJdkVersion、urlPattern、"
                        + "shellClassName、injectorClassName、pass、key、paramName、template、headerName、headerValue、"
                        + "encryptor、implementationClass、shellClassBase64、debug。可选值目录见「使用帮助」页签。");
    }

    @Override
    public void doHelp(Map<String, Object> customArgs, final IResultOutput resultOutput) {
        PluginRuntime.run(resultOutput, new PluginRuntime.Task() {
            @Override
            public void run(IResultOutput output) {
                MemShellRequest request = MemShellRequest.from(customArgs);
                output.startPrintln("开始生成内存马");
                request.printSummary(output);
                if (request.printFieldErrors(output)) {
                    return;
                }
                long start = System.currentTimeMillis();
                Output.memShellResult(output, request.generate(), System.currentTimeMillis() - start);
            }
        });
    }
}
