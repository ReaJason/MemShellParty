package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.desktop.memshell.service.ResultInfoService;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import me.gv7.woodpecker.plugin.IResultOutput;

/**
 * 结果文本输出：信息行带 {@code [+]}/{@code [*]} 前缀，打包产物用 {@code rawPrintln} 原样输出，
 * 方便在输出面板里直接框选复制。
 */
final class Output {

    private Output() {
    }

    static void info(IResultOutput output, String message) {
        output.infoPrintln(message);
    }

    static void success(IResultOutput output, String message) {
        output.successPrintln(message);
    }

    static void warn(IResultOutput output, String message) {
        output.warningPrintln(message);
    }

    static void fail(IResultOutput output, String message) {
        output.failPrintln(message);
    }

    /**
     * 内存马结果：先信息行（工具参数/类名与大小），再打包产物。
     */
    static void memShellResult(IResultOutput output, DesktopMemShellGenerateResult result, long elapsedMillis) {
        MemShellResult memShellResult = result.getMemShellResult();
        for (InfoRow row : ResultInfoService.describe(result)) {
            info(output, row.getName() + ": " + row.getValue());
        }
        String urlPattern = memShellResult.getInjectorConfig() == null
                ? "" : memShellResult.getInjectorConfig().getUrlPattern();
        if (urlPattern != null && !urlPattern.isEmpty()) {
            info(output, "挂载地址: " + urlPattern);
        }
        packSection(output, result.getPackMethod(), result.getPackResult(),
                result.isJarOutput() || result.isAgentOutput());
        success(output, "生成完成，耗时 " + elapsedMillis + " ms"
                + "（工具客户端用上面输出的密码/密钥/请求头配置）");
    }

    /**
     * 探测马结果：探测方式与回显参数，再打包产物。
     */
    static void probeShellResult(IResultOutput output, DesktopProbeShellGenerateResult result, long elapsedMillis) {
        ProbeShellResult probeShellResult = result.getProbeShellResult();
        ProbeConfig probeConfig = probeShellResult.getProbeConfig();
        if (probeConfig != null) {
            info(output, "探测方式: " + probeConfig.getProbeMethod() + " / " + probeConfig.getProbeContent());
        }
        appendProbeContent(output, probeShellResult.getProbeContentConfig());
        info(output, "探测马类名: " + probeShellResult.getShellClassName()
                + " (" + probeShellResult.getShellSize() + " bytes)");
        packSection(output, result.getPackMethod(), result.getPackResult(), false);
        success(output, "生成完成，耗时 " + elapsedMillis + " ms");
    }

    private static void appendProbeContent(IResultOutput output, ProbeContentConfig contentConfig) {
        if (contentConfig instanceof DnsLogConfig) {
            info(output, "DNSLog 域名: " + ((DnsLogConfig) contentConfig).getHost());
        } else if (contentConfig instanceof SleepConfig) {
            SleepConfig sleepConfig = (SleepConfig) contentConfig;
            info(output, "休眠服务: " + sleepConfig.getServer() + "，秒数: " + sleepConfig.getSeconds());
        } else if (contentConfig instanceof ResponseConfig) {
            ResponseConfig responseConfig = (ResponseConfig) contentConfig;
            info(output, "目标服务: " + responseConfig.getServer());
            if (responseConfig.getRespHeaderName() != null && !responseConfig.getRespHeaderName().isEmpty()) {
                info(output, "响应头名称: " + responseConfig.getRespHeaderName());
            }
            info(output, "回显参数名: " + responseConfig.getReqParamName());
            if (responseConfig.getCommandTemplate() != null) {
                info(output, "命令模板: " + responseConfig.getCommandTemplate());
            }
        }
    }

    /**
     * 打包产物：逐字输出，Jar 类产物额外提示 Base64 解码后为 Jar 字节。
     */
    private static void packSection(IResultOutput output, String packMethod, String packResult, boolean jarLike) {
        String value = packResult == null ? "" : packResult;
        info(output, "打包结果（" + packMethod
                + (jarLike ? "，Base64 解码后为 Jar 字节" : "")
                + "，共 " + value.length() + " 字符）");
        output.rawPrintln(value);
    }
}
