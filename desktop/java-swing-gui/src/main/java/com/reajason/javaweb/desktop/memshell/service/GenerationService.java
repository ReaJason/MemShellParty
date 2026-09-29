package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.config.ProxyConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 进程内生成 + 打包，流程对齐 boot 端 MemShellGeneratorController 与 MemShellGenerateRequest.parseShellToolConfig。
 */
public class GenerationService {

    private static final String UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String CLASS_NAME_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final CustomClassNameParser customClassNameParser = new CustomClassNameParser();

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
                // 对齐 web 端 transformer.ts：SpringGzipJDK17 系打包方式强制伪装成
                // org.springframework.expression 下的类，忽略用户填写的注入器类名
                .injectorClassName(isSpringGzipJdk17RelatedPacker(s.getPackingMethod())
                        ? generateSpringExpressionInjectorClassName()
                        : blankToNull(s.getInjectorClassName()))
                .staticInitialize(s.isStaticInitialize())
                .build();

        ShellToolConfig shellToolConfig = buildShellToolConfig(s);
        // Custom 且类名留空时从字节码解析（等效 web 端 /api/className 自动填充），
        // 否则 MemShellGenerator 会用随机名 rename 导致与原类名不一致
        if (ShellTool.Custom.equals(s.getShellTool()) && isBlank(s.getShellClassName())
                && !isBlank(s.getShellClassBase64())) {
            shellToolConfig.setShellClassName(customClassNameParser.parseClassNameFromBase64(s.getShellClassBase64()));
        }
        MemShellResult result = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);

        String packMethod = s.getPackingMethod();
        Packers packers;
        try {
            packers = Packers.valueOf(packMethod);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("未知打包方式: " + packMethod, e);
        }
        Packer packer = packers.getInstance();
        if (packer instanceof AggregatePacker) {
            return new DesktopMemShellGenerateResult(result, packMethod,
                    ((AggregatePacker) packer).packAll(result.toClassPackerConfig()));
        }
        if (packer instanceof JarPacker) {
            byte[] jarBytes = ((JarPacker) packer).packBytes(result.toJarPackerConfig());
            return new DesktopMemShellGenerateResult(result, packMethod,
                    Base64.getEncoder().encodeToString(jarBytes));
        }
        return new DesktopMemShellGenerateResult(result, packMethod, packer.pack(result.toClassPackerConfig()));
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

    static boolean isSpringGzipJdk17RelatedPacker(String packer) {
        return packer != null && packer.endsWith("SpringGzipJDK17");
    }

    static String generateSpringExpressionInjectorClassName() {
        StringBuilder randomName = new StringBuilder(5);
        for (int i = 0; i < 5; i++) {
            randomName.append(CLASS_NAME_LETTERS.charAt(RANDOM.nextInt(CLASS_NAME_LETTERS.length())));
        }
        return "org.springframework.expression."
                + UPPERCASE_LETTERS.charAt(RANDOM.nextInt(UPPERCASE_LETTERS.length()))
                + randomName + "Util";
    }

    private static int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String blankToNull(String s) {
        return s == null || s.trim().isEmpty() ? null : s;
    }

    private static String blankToDefault(String s, String d) {
        return s == null || s.trim().isEmpty() ? d : s;
    }
}
