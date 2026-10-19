package com.reajason.javaweb.probe;

import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Probe 混淆：PROBE_COMMON 契约下 toString / doFilter 等入口保留，输出类名一致且可被 ASM 解析。
 */
class ProbeShellGeneratorObfuscationTest {

    private static Set<String> methodNames(byte[] classBytes) {
        Set<String> names = new LinkedHashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return names;
    }

    private static ProbeConfig probeConfig(ObfuscationConfig obfuscation) {
        return ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Filter)
                .shellClassName("com.example.ProbeSample")
                .obfuscation(obfuscation)
                .build();
    }

    private static ResponseConfig contentConfig() {
        return ResponseConfig.builder().server("Tomcat").build();
    }

    @Test
    void shouldStayUntouchedWhenDisabled() {
        // 开关关闭：混淆钩子完全旁路（逐字节一致由 ClassObfuscationTest.shouldPassThroughWhenDisabled 覆盖，
        // 生成流程自身带随机值，两次独立生成不能互比），这里断言元数据为空且产出可解析
        ProbeConfig off = probeConfig(ObfuscationConfig.defaults());
        ProbeShellResult result = ProbeShellGenerator.generate(off, contentConfig());
        assertNull(result.getObfuscationInfo(), "enabled=false 时不应产生混淆元数据");
        assertEquals("com.example.ProbeSample", new ClassReader(result.getShellBytes()).getClassName().replace('/', '.'));
    }

    @Test
    void shouldObfuscateProbeAndKeepProbeCommonContracts() {
        ProbeShellResult plain = ProbeShellGenerator.generate(
                probeConfig(ObfuscationConfig.defaults()), contentConfig());
        Set<String> originMethods = methodNames(plain.getShellBytes());

        ProbeConfig config = probeConfig(ObfuscationConfig.enabled());
        ProbeShellResult result = ProbeShellGenerator.generate(config, contentConfig());
        byte[] bytes = result.getShellBytes();
        // 类名保持一致、可被 ASM 解析
        assertEquals("com.example.ProbeSample", new ClassReader(bytes).getClassName().replace('/', '.'));
        // PROBE_COMMON 契约：原类中声明过的契约方法必须存活（交集断言，不臆测方法存在）
        Set<String> methods = methodNames(bytes);
        Set<String> contractNames = contractNames(originMethods);
        for (String name : contractNames) {
            assertTrue(methods.contains(name), "contract method " + name + " should survive: " + methods);
        }
        // 非契约方法被改名（以该探针类必有的工具方法为代表）
        assertTrue(originMethods.contains("getDataFromReq"), "fixture assumption: probe declares getDataFromReq");
        assertFalse(methods.contains("getDataFromReq"), "getDataFromReq should be renamed: " + methods);
        assertFalse(methods.contains("writeHeader"), "writeHeader should be renamed: " + methods);
        // 元数据回填
        assertNotNull(result.getObfuscationInfo());
        assertTrue(result.getObfuscationInfo().isEnabled());
        assertTrue(result.getObfuscationInfo().getOriginalShellSize() > 0);
        assertTrue(result.getObfuscationInfo().getObfuscatedShellSize() > 0);
    }

    private static Set<String> contractNames(Set<String> methodNames) {
        Set<String> names = new LinkedHashSet<>();
        for (MethodSignature sig : MethodContracts.PROBE_COMMON) {
            if (methodNames.contains(sig.getName())) {
                names.add(sig.getName());
            }
        }
        return names;
    }
}
