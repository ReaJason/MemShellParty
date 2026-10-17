package com.reajason.javaweb.woodpecker;

import me.gv7.woodpecker.plugin.IArg;
import me.gv7.woodpecker.plugin.IArgsUsageBinder;
import me.gv7.woodpecker.plugin.IHelper;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IResultOutput;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 「探测马生成」页签：四种探测方式（DNSLog / ResponseBody / ResponseHeader / 延时）× 探测内容 × 打包方式。
 *
 * <p>探测马没有注入器，所以候选打包方式里排除了 Agent/XXLJOB/Jar 三类（与桌面端探测马页一致），
 * 选到不支持的打包方式会在执行时被拒掉。
 */
public class ProbeShellHelper implements IHelper {

    private final IPluginHelper pluginHelper;

    public ProbeShellHelper(IPluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Override
    public String getHelperTabCaption() {
        return "探测马生成";
    }

    @Override
    public IArgsUsageBinder getHelperCutomArgs() {
        // 声明顺序 = Args 文本框里的预填顺序
        List<IArg> args = new ArrayList<IArg>();
        args.add(Args.arg(pluginHelper, "probeMethod", "ResponseBody",
                "探测方式：ResponseBody（响应体回显）/ ResponseHeader（响应头回显）/ DNSLog / Sleep（延时），默认 ResponseBody"));
        args.add(Args.arg(pluginHelper, "byPassJavaModule", "false",
                "移除 JDK9+ 模块限制，true/false；目标 JDK 为 9+ 时自动生效，填 true 可强制开启"));
        args.add(Args.arg(pluginHelper, "shrink", "true", "精简生成字节码，true/false"));
        args.add(Args.arg(pluginHelper, "staticInitialize", "true", "追加静态代码块初始化，true/false"));
        args.add(Args.arg(pluginHelper, "lambdaSuffix", "false", "类名追加 lambda 风格后缀，true/false"));
        args.add(Args.arg(pluginHelper, "packingMethod", "DefaultBase64",
                "打包方式，如 DefaultBase64 / GzipBase64 / JSP / BCEL / ScriptEngine（见「使用帮助」）"));

        args.add(Args.arg(pluginHelper, "probeContent", "",
                "探测内容：ResponseBody/ResponseHeader 支持 Command/Bytecode/ScriptEngine/Filter，DNSLog 支持 JDK/Server，Sleep 支持 Server；"
                        + "留空取当前探测方式的首个可用项，换探测方式后旧值不可用会自动回落"));
        args.add(Args.arg(pluginHelper, "server", "",
                "目标服务（ResponseBody/ResponseHeader 与 Sleep 用），如 Tomcat / Jetty / Undertow / SpringWebFlux"));
        args.add(Args.arg(pluginHelper, "host", "",
                "DNSLog 域名（DNSLog 方式必填），如 xxx.dnslog.cn"));
        args.add(Args.arg(pluginHelper, "seconds", "",
                "Sleep 延时秒数（Sleep 方式，需大于 0），留空默认 5"));
        args.add(Args.arg(pluginHelper, "sleepServer", "",
                "Sleep 方式的休眠服务，留空默认 Tomcat"));
        args.add(Args.arg(pluginHelper, "reqParamName", "",
                "ResponseBody/ResponseHeader 回显参数名，留空随机（结果里会打印实际取值）"));
        args.add(Args.arg(pluginHelper, "commandTemplate", "",
                "命令模板，{command} 为命令占位符"));
        args.add(Args.arg(pluginHelper, "respHeaderName", "",
                "ResponseHeader 回显头名称，留空随机（X- 前缀；结果里会打印实际取值）"));
        args.add(Args.arg(pluginHelper, "shellClassName", "",
                "探测马类名，留空随机"));
        args.add(Args.arg(pluginHelper, "targetJdkVersion", "",
                "目标 JRE 版本 50/52/53/55/61/65，留空自动"));
        args.add(Args.arg(pluginHelper, "debug", "",
                "目标服务端打印调试日志，true/false，留空默认关"));
        return Args.binder(pluginHelper, args,
                "Args 文本框里一行一个「参数名=值」（如 probeMethod=DNSLog、host=xxx.dnslog.cn），只写要改的；"
                        + "上面已按默认值预填常用参数，点 Generate 执行，结果在下方 Result。"
                        + "随机出来的回显参数名/类名会打印在结果里；"
                        + "「?」可查看全部参数与说明，可选参数：probeContent、server、host、seconds、sleepServer、"
                        + "reqParamName、commandTemplate、respHeaderName、shellClassName、targetJdkVersion、debug。"
                        + "可选值目录见「使用帮助」页签。");
    }

    @Override
    public void doHelp(Map<String, Object> customArgs, final IResultOutput resultOutput) {
        PluginRuntime.run(resultOutput, new PluginRuntime.Task() {
            @Override
            public void run(IResultOutput output) {
                ProbeShellRequest request = ProbeShellRequest.from(customArgs);
                output.startPrintln("开始生成探测马");
                request.printSummary(output);
                if (request.printFieldErrors(output)) {
                    return;
                }
                long start = System.currentTimeMillis();
                Output.probeShellResult(output, request.generate(), System.currentTimeMillis() - start);
            }
        });
    }
}
