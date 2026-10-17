package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 进程内生成 + 打包，流程对齐 boot 端 MemShellGeneratorController 与 MemShellGenerator.generate 的 Map 重载。
 */
public class GenerationService {

    private final CustomClassNameParser customClassNameParser = new CustomClassNameParser();
    private final MemShellGenerator memShellGenerator = new MemShellGenerator();

    public DesktopMemShellGenerateResult generate(MemShellFormState s) {
        Packers packers = parsePacker(s.getPackingMethod());
        // SpringGzipJDK17 系打包方式要求类伪装成 org.springframework.expression 下的类；
        // 调用方没给合法类名时用词表补齐，不再生成随机大小写字母
        String requestedInjectorClassName = blankToNull(s.getInjectorClassName());
        String injectorClassName = packers.requiresSpringExpressionPackage()
                && !Packers.isSpringExpressionClassName(requestedInjectorClassName)
                ? packers.generateSpringExpressionClassName()
                : requestedInjectorClassName;
        MemShellResult result = generateShell(s, injectorClassName);

        Packer packer = packers.getInstance();
        if (packer instanceof AggregatePacker) {
            return new DesktopMemShellGenerateResult(result, s.getPackingMethod(),
                    ((AggregatePacker) packer).packAll(ClassPackerConfig.from(result)));
        }
        if (packer instanceof JarPacker) {
            byte[] jarBytes = ((JarPacker) packer).packBytes(JarPackerConfig.from(result));
            return new DesktopMemShellGenerateResult(result, s.getPackingMethod(),
                    Base64.getEncoder().encodeToString(jarBytes));
        }
        return new DesktopMemShellGenerateResult(result, s.getPackingMethod(), packer.pack(ClassPackerConfig.from(result)));
    }

    /**
     * 只生成不打包：返回原始 {@link MemShellResult}（含 injector 字节），供不走路程打包的宿主
     * （如 Shiro 反序列化注入：injector 字节直接进 gadget 链）复用同一份表单状态。
     */
    public MemShellResult generateShell(MemShellFormState s) {
        return generateShell(s, blankToNull(s.getInjectorClassName()));
    }

    private MemShellResult generateShell(MemShellFormState s, String injectorClassName) {
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
                .injectorClassName(injectorClassName)
                .staticInitialize(s.isStaticInitialize())
                .build();

        Map<String, String> shellToolParams = resolveShellToolParams(s);
        return memShellGenerator.generate(shellConfig, injectorConfig, shellToolParams);
    }

    /**
     * 平铺表单字段为原始参数 map：key 就是各工具 config 的字段名（pass / key / paramName / template…），
     * 并按配置目录过滤出当前工具真正支持的参数 —— 切换工具时状态已整体清空，这里再兜一道，
     * 扩展面板直接写状态写错了名字也不会把生成流程炸掉；空值跳过走 builder 的随机默认值。
     *
     * <p>Custom 且类名留空时从字节码解析（等效 web 端 /api/className 自动填充），
     * 否则 MemShellGenerator 会用随机名 rename 导致与原类名不一致。
     */
    private Map<String, String> resolveShellToolParams(MemShellFormState s) {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("shellClassName", s.getShellClassName());
        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(s.getShellTool())) {
            params.put(param.getName(), s.getToolParam(param.getName()));
        }
        String shellClassBase64 = s.getToolParam(MemShellFormState.PARAM_SHELL_CLASS_BASE64);
        if (ShellTool.Custom.equals(s.getShellTool()) && isBlank(s.getShellClassName())
                && !isBlank(shellClassBase64)) {
            params.put("shellClassName", customClassNameParser.parseClassNameFromBase64(shellClassBase64));
        }
        return params;
    }

    private static Packers parsePacker(String packMethod) {
        try {
            return Packers.valueOf(packMethod);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("未知打包方式: " + packMethod, e);
        }
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
