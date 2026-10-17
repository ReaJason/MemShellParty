package com.reajason.javaweb.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
class ProbeGeneratorTest {

    @Test
    @SneakyThrows
    void generate() {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .build();
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(Server.Jetty)
                .reqParamName("payload")
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseConfig);
        System.out.println(probeResult.getShellBytesBase64Str());
//        Files.write(Paths.get("hello.class"), probeResult.getShellBytes());
        System.out.println(Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                probeResult.getShellClassName(), probeResult.getShellBytes(), probeResult.getShellBytesBase64Str(),
                probeResult.getProbeConfig() != null && probeResult.getProbeConfig().needByPassJavaModule())));
    }
}