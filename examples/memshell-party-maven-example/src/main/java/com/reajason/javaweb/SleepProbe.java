package com.reajason.javaweb;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.SleepConfig;

import static com.reajason.javaweb.Server.Tomcat;

/**
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

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(result.toClassPackerConfig()));
    }
}
