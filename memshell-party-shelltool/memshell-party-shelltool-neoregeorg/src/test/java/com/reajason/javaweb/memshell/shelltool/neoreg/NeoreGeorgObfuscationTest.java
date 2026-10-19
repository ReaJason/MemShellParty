package com.reajason.javaweb.memshell.shelltool.neoreg;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.obfuscation.ClassObfuscation;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationTarget;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NeoreGeorg 模板的 doFilter 承载全部代理逻辑，字节码逼近 64KB Code 属性上限；
 * STRONG 档的 XOR/控制流变换会把方法体撑爆（MethodTooLargeException），
 * 混淆门面应沿降级阶梯（STRONG → LIGHT → RENAME_ONLY）落到可用档位而不是直接失败。
 */
class NeoreGeorgObfuscationTest {

    @Test
    void filterShellSurvivesObfuscation() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.NeoreGeorg)
                .shellType(ShellType.FILTER)
                .targetJreVersion(Opcodes.V1_8)
                .build();
        NeoreGeorgConfig neoreGeorgConfig = NeoreGeorgConfig.builder()
                .shellTemplateClassName(NeoreGeorgFilter.class.getName())
                .shellClassName(CommonUtil.generateClassName())
                .headerName("Referer")
                .headerValue("https://example.com/")
                .build();
        byte[] shellBytes = new NeoreGeorgGenerator(shellConfig, neoreGeorgConfig).getBytes();

        byte[] output = ClassObfuscation.obfuscate(shellBytes, neoreGeorgConfig.getShellClassName(),
                Opcodes.V1_8, ObfuscationTarget.SHELL, ObfuscationConfig.enabled(),
                MethodContracts.CONSERVATIVE, Collections.<String, byte[]>emptyMap());

        ClassReader cr = new ClassReader(output);
        assertEquals(neoreGeorgConfig.getShellClassName(), cr.getClassName().replace('/', '.'));
        int outVersion = cr.readShort(6) & 0xFFFF;
        assertTrue(outVersion <= Opcodes.V1_8, "output major version " + outVersion + " should be <= 52");
        // 降级只应落到 LIGHT（保留 AES）：headerValue 密文存储，常量池不留明文。
        // 若降到 RENAME_ONLY（AES 关闭），这里会以明文常量出现，说明阶梯降过头了
        String raw = new String(output, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(neoreGeorgConfig.getHeaderValue()),
                "headerValue should be AES-encrypted (LIGHT rung), not plaintext");
    }
}
