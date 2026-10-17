package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.utils.StringUtils;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 调用方只保证传了必要字段（反序列化出来的配置，没填的字段就是 null / 0），缺的由生成入口补齐并写回，
 * 见 {@link MemShellGenerator#generate}、{@link ProbeShellGenerator#generate}。
 *
 * @author ReaJason
 */
class MissingParamDefaultsTest {

    @Test
    void memShellParamsAreFilledAtEntryPoint() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .serverVersion(null)
                .targetJreVersion(0)
                .build();

        // injectorConfig 整个没传（客户端省略子对象）也要能生成
        MemShellResult result = new MemShellGenerator().generate(shellConfig, null, Collections.emptyMap());

        assertEquals("unknown", result.getShellConfig().getServerVersion());
        assertEquals(Opcodes.V1_6, result.getShellConfig().getTargetJreVersion());
        assertEquals("/*", result.getInjectorConfig().getUrlPattern());
        assertFalse(StringUtils.isBlank(result.getShellClassName()));
        assertFalse(StringUtils.isBlank(result.getInjectorClassName()));
    }

    @Test
    void probeParamsAreFilledAtEntryPoint() {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .targetJreVersion(0)
                .build();

        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig,
                ResponseConfig.builder().server(Server.Tomcat).reqParamName("payload").build());

        assertEquals(Opcodes.V1_6, result.getProbeConfig().getTargetJreVersion());
        assertFalse(StringUtils.isBlank(result.getShellClassName()));
    }
}
