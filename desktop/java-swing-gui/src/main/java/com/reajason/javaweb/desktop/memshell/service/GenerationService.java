package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class GenerationService {

    public DesktopMemShellGenerateResult generate(MemShellFormState s) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(s.getServer())
                .serverVersion(s.getServerVersion())
                .shellTool(s.getShellTool())
                .shellType(s.getShellType())
                .targetJreVersion(parseInt(s.getTargetJdkVersion(), 50))
                .debug(s.isDebug())
                .byPassJavaModule(s.isByPassJavaModule())
                .probe(s.isProbe())
                .shrink(s.isShrink())
                .lambdaSuffix(s.isLambdaSuffix())
                .build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern(blankToDefault(s.getUrlPattern(), "/*"))
                .injectorClassName(blankToNull(s.getInjectorClassName()))
                .staticInitialize(s.isStaticInitialize())
                .build();

        ShellToolConfig shellToolConfig = buildShellToolConfig(s);
        MemShellResult memShellResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);

        String packMethod = s.getPackingMethod();
        Packers packers = Packers.fromName(packMethod);
        Packer<?> packer = packers.getInstance();
        String packResult;
        if (packer instanceof JarPacker) {
            JarPacker jarPacker = (JarPacker) packer;
            packResult = Base64.getEncoder().encodeToString(jarPacker.packBytes(memShellResult.toJarPackerConfig()));
        } else {
            ClassPackerConfig<Object> classPackerConfig = cast(memShellResult.toClassPackerConfig());
            Map<String, Object> rawCustom = new LinkedHashMap<>(s.getPackerCustomConfig());
            classPackerConfig.setCustomConfig(((Packer<Object>) packer).resolveCustomConfig(rawCustom));
            packResult = ((Packer<Object>) packer).pack(classPackerConfig);
        }
        return new DesktopMemShellGenerateResult(memShellResult, packMethod, packResult);
    }

    @SuppressWarnings("unchecked")
    private static ClassPackerConfig<Object> cast(ClassPackerConfig<?> c) {
        return (ClassPackerConfig<Object>) c;
    }

    private ShellToolConfig buildShellToolConfig(MemShellFormState s) {
        String tool = s.getShellTool();
        if (ShellTool.Godzilla.equals(tool)) {
            return GodzillaConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .pass(blankToNull(s.getGodzillaPass()))
                    .key(blankToNull(s.getGodzillaKey()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.Behinder.equals(tool)) {
            return BehinderConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .pass(blankToNull(s.getBehinderPass()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.AntSword.equals(tool)) {
            return AntSwordConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .pass(blankToNull(s.getAntSwordPass()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.Suo5.equals(tool) || ShellTool.Suo5v2.equals(tool)) {
            return Suo5Config.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.NeoreGeorg.equals(tool)) {
            return NeoreGeorgConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.Proxy.equals(tool)) {
            return ProxyConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .build();
        }
        if (ShellTool.Custom.equals(tool)) {
            return CustomConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .shellClassBase64(blankToNull(s.getShellClassBase64()))
                    .build();
        }
        if (ShellTool.Command.equals(tool)) {
            return CommandConfig.builder()
                    .shellClassName(blankToNull(s.getShellClassName()))
                    .paramName(blankToNull(s.getCommandParamName()))
                    .headerName(blankToNull(s.getHeaderName()))
                    .headerValue(blankToNull(s.getHeaderValue()))
                    .template(blankToNull(s.getCommandTemplate()))
                    .encryptor(CommandConfig.Encryptor.fromString(blankToNull(s.getEncryptor())))
                    .implementationClass(CommandConfig.ImplementationClass.fromString(blankToNull(s.getImplementationClass())))
                    .build();
        }
        throw new IllegalArgumentException("Unsupported shell tool: " + tool);
    }

    private int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.trim().isEmpty() ? null : s;
    }

    private static String blankToDefault(String s, String d) {
        return s == null || s.trim().isEmpty() ? d : s;
    }
}
