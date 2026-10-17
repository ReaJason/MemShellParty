package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.config.SleepConfig;

/**
 * 探测马进程内生成 + 打包，流程对齐 boot 端 GenerationService.generateProbeShell。
 */
public class ProbeGenerationService {

    public DesktopProbeShellGenerateResult generate(ProbeShellFormState s) {
        String packMethod = s.getPackingMethod();
        Packers packers;
        try {
            packers = Packers.valueOf(packMethod);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("未知打包方式: " + packMethod, e);
        }
        ProbeMethod method = ProbeMethod.valueOf(s.getProbeMethod());
        // 留空时由 ProbeShellGenerator 随机生成；SpringGzipJDK17 系打包方式则必须落在
        // org.springframework.expression 包下，调用方没给合法类名时用词表补齐
        String shellClassName = blankToNull(s.getShellClassName());
        if (packers.requiresSpringExpressionPackage()
                && !Packers.isSpringExpressionClassName(shellClassName)) {
            shellClassName = packers.generateSpringExpressionClassName();
        }
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(method)
                .probeContent(ProbeContent.valueOf(s.getProbeContent()))
                .shellClassName(shellClassName)
                .targetJreVersion(parseInt(s.getTargetJdkVersion(), 50))
                .debug(s.isDebug())
                .byPassJavaModule(s.isByPassJavaModule())
                .shrink(s.isShrink())
                .staticInitialize(s.isStaticInitialize())
                .lambdaSuffix(s.isLambdaSuffix())
                .build();

        ProbeContentConfig contentConfig = buildContentConfig(s, method);
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);

        Packer packer = packers.getInstance();
        ClassPackerConfig packerConfig = ClassPackerConfig.of(result.getShellClassName(), result.getShellBytes(),
                result.getShellBytesBase64Str(), result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule());
        if (packer instanceof AggregatePacker) {
            return new DesktopProbeShellGenerateResult(result, packMethod,
                    ((AggregatePacker) packer).packAll(packerConfig));
        }
        return new DesktopProbeShellGenerateResult(result, packMethod, packer.pack(packerConfig));
    }

    /**
     * 对齐 boot ProbeShellGenerateRequest.parseProbeContentConfig。
     */
    private ProbeContentConfig buildContentConfig(ProbeShellFormState s, ProbeMethod method) {
        if (ProbeMethod.DNSLog.equals(method)) {
            return DnsLogConfig.builder()
                    .host(blankToNull(s.getHost()))
                    .build();
        }
        if (ProbeMethod.Sleep.equals(method)) {
            return SleepConfig.builder()
                    .seconds(parseInt(s.getSeconds(), 5))
                    .server(blankToNull(s.getSleepServer()))
                    .build();
        }
        if (ProbeMethod.ResponseBody.equals(method)) {
            return ResponseConfig.builder()
                    .server(blankToNull(s.getServer()))
                    // 自定义 builder 忽略空白值，留空时回落到内置随机参数名
                    .reqParamName(s.getReqParamName())
                    .commandTemplate(blankToNull(s.getCommandTemplate()))
                    .build();
        }
        if (ProbeMethod.ResponseHeader.equals(method)) {
            return ResponseConfig.builder()
                    .server(blankToNull(s.getServer()))
                    .reqParamName(s.getReqParamName())
                    .commandTemplate(blankToNull(s.getCommandTemplate()))
                    // 留空由生成器随机生成 X- 前缀头名，并写回结果
                    .respHeaderName(blankToNull(s.getRespHeaderName()))
                    .build();
        }
        throw new IllegalArgumentException("Unsupported probe method: " + method);
    }

    private static int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.trim().isEmpty() ? null : s;
    }
}
