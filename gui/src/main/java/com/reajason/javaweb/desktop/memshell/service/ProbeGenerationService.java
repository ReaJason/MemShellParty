package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.config.SleepConfig;

/**
 * 探测马进程内生成 + 打包，流程对齐 boot 端 GenerationService.generateProbeShell。
 */
public class ProbeGenerationService {

    public DesktopProbeShellGenerateResult generate(ProbeShellFormState s) {
        ProbeMethod method = ProbeMethod.valueOf(s.getProbeMethod());
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(method)
                .probeContent(ProbeContent.valueOf(s.getProbeContent()))
                // 留空交给 ProbeShellGenerator 随机生成（显式 null 会覆盖 @Builder.Default）
                .shellClassName(blankToNull(s.getShellClassName()))
                .targetJreVersion(parseInt(s.getTargetJdkVersion(), 50))
                .debug(s.isDebug())
                .byPassJavaModule(s.isByPassJavaModule())
                .shrink(s.isShrink())
                .staticInitialize(s.isStaticInitialize())
                .lambdaSuffix(s.isLambdaSuffix())
                .build();

        ProbeContentConfig contentConfig = buildContentConfig(s, method);
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);

        String packMethod = s.getPackingMethod();
        Packers packers;
        try {
            packers = Packers.valueOf(packMethod);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("未知打包方式: " + packMethod, e);
        }
        Packer packer = packers.getInstance();
        if (packer instanceof AggregatePacker) {
            return new DesktopProbeShellGenerateResult(result, packMethod,
                    ((AggregatePacker) packer).packAll(result.toClassPackerConfig()));
        }
        return new DesktopProbeShellGenerateResult(result, packMethod, packer.pack(result.toClassPackerConfig()));
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
            return ResponseBodyConfig.builder()
                    .server(blankToNull(s.getServer()))
                    // 自定义 builder 忽略空白值，留空时回落到内置随机参数名
                    .reqParamName(s.getReqParamName())
                    .commandTemplate(blankToNull(s.getCommandTemplate()))
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
