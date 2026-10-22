package com.reajason.javaweb.examples.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.ToolConfigFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * MemShellGenerator 的查询面：先拿到「服务端 × 工具 × 挂载类型」支持矩阵，再按轴查。
 * 生成之前先用它确认目标组合成立，比生成失败后猜原因可靠。
 *
 * @author ReaJason
 * @since 2026/10/22
 */
public class Capabilities {
    public static void main(String[] args) {
        MemShellGenerator generator = new MemShellGenerator();
        MemShellGenerator.ShellTypeCatalog catalog = generator.getShellTypeCatalog();

        // 整张矩阵：LinkedHashMap，服务端/工具/类型都保持注册顺序
        System.out.println("已注册服务端：" + generator.getSupportedServers());
        System.out.println("已注册工具：" + generator.getSupportedTools());
        System.out.println();
        for (Map.Entry<String, Map<String, List<String>>> server : catalog.asMap().entrySet()) {
            for (Map.Entry<String, List<String>> tool : server.getValue().entrySet()) {
                System.out.println(server.getKey() + " / " + tool.getKey() + " -> " + tool.getValue());
            }
        }

        System.out.println();
        System.out.println("能跑 Godzilla 的服务端：" + catalog.getServersSupporting(ShellTool.Godzilla));
        System.out.println(Server.Tomcat + " 上可用的工具：" + catalog.getShellTools(Server.Tomcat));
        System.out.println(Server.Tomcat + " / Godzilla 的挂载类型："
                + catalog.getShellTypes(Server.Tomcat, ShellTool.Godzilla));
        System.out.println();

        // 支持矩阵已经按 server 的注入器映射过滤过：Agent 类型只出现在真正有 agent 注入器的组合里
        List<String> agentTools = new ArrayList<>();
        for (String tool : catalog.getShellTools(Server.Tomcat)) {
            if (catalog.getShellTypes(Server.Tomcat, tool).contains(ShellType.AGENT_FILTER_CHAIN)) {
                agentTools.add(tool);
            }
        }
        System.out.println(Server.Tomcat + " 支持 " + ShellType.AGENT_FILTER_CHAIN + " 的工具：" + agentTools);
        System.out.println();

        // 工具参数目录：GUI 动态表单、REST/MCP 的参数校验都从这份注解描述来
        for (ToolConfigFactory.ToolConfigDescriptor descriptor : ToolConfigFactory.describeAll()) {
            StringBuilder params = new StringBuilder();
            for (ToolConfigFactory.ConfigParam param : descriptor.getParams()) {
                if (params.length() > 0) {
                    params.append(", ");
                }
                params.append(param.getName()).append('(').append(param.getType()).append(')');
            }
            System.out.println(descriptor.getTool() + " 参数：" + params);
        }
    }
}
