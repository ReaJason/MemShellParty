package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.config.ProxyConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;

import static com.reajason.javaweb.memshell.ShellTool.AntSword;
import static com.reajason.javaweb.memshell.ShellTool.Behinder;
import static com.reajason.javaweb.memshell.ShellTool.Command;
import static com.reajason.javaweb.memshell.ShellTool.Custom;
import static com.reajason.javaweb.memshell.ShellTool.Godzilla;
import static com.reajason.javaweb.memshell.ShellTool.NeoreGeorg;
import static com.reajason.javaweb.memshell.ShellTool.Proxy;
import static com.reajason.javaweb.memshell.ShellTool.Suo5;
import static com.reajason.javaweb.memshell.ShellTool.Suo5v2;

/**
 * 按 shellTool 把扁平参数映射为对应的 {@link ShellToolConfig}。
 * <p>
 * REST 与 MCP 两个入口共用此映射，避免各自维护一份 switch 而随 shellTool 增加而漂移。
 *
 * @author ReaJason
 */
public final class ShellToolConfigMapper {

    private ShellToolConfigMapper() {
    }

    public static ShellToolConfig map(String shellTool, ShellToolParams params) {
        return switch (shellTool) {
            case Godzilla -> GodzillaConfig.builder()
                    .shellClassName(params.shellClassName())
                    .pass(params.godzillaPass())
                    .key(params.godzillaKey())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .build();
            case Behinder -> BehinderConfig.builder()
                    .shellClassName(params.shellClassName())
                    .pass(params.behinderPass())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .build();
            case Command -> CommandConfig.builder()
                    .shellClassName(params.shellClassName())
                    .paramName(params.commandParamName())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .template(params.commandTemplate())
                    .encryptor(CommandConfig.Encryptor.fromString(params.encryptor()))
                    .implementationClass(CommandConfig.ImplementationClass.fromString(params.implementationClass()))
                    .build();
            case Suo5, Suo5v2 -> Suo5Config.builder()
                    .shellClassName(params.shellClassName())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .build();
            case AntSword -> AntSwordConfig.builder()
                    .shellClassName(params.shellClassName())
                    .pass(params.antSwordPass())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .build();
            case NeoreGeorg -> NeoreGeorgConfig.builder()
                    .shellClassName(params.shellClassName())
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .build();
            case Custom -> CustomConfig.builder()
                    .shellClassBase64(params.shellClassBase64())
                    .shellClassName(params.shellClassName())
                    .build();
            case Proxy -> ProxyConfig.builder()
                    .headerName(params.headerName())
                    .headerValue(params.headerValue())
                    .shellClassName(params.shellClassName())
                    .build();
            default -> throw new UnsupportedOperationException("unknown shell tool " + shellTool);
        };
    }
}
