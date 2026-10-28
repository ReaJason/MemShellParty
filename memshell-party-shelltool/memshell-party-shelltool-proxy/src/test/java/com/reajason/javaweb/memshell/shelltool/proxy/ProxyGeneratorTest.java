package com.reajason.javaweb.memshell.shelltool.proxy;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ProxyGeneratorTest {

    @ParameterizedTest
    @ValueSource(ints = {Opcodes.V17, Opcodes.V21})
    void embeddedProxyHttpUsesConfiguredTargetJreVersion(int targetJreVersion) {
        ProxyConfig config = ProxyConfig.builder()
                .shellTemplateClassName(ProxyDubboService.class.getName())
                .shellClassName("org.apache.utils.GeneratedProxyDubboService")
                .build();
        byte[] shellBytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.Dubbo)
                .shellType(ShellType.ALIBABA_DUBBO_SERVICE)
                .targetJreVersion(targetJreVersion)
                .build(), config).getBytes();

        assertEquals(targetJreVersion, new ClassReader(shellBytes).readUnsignedShort(6));
        byte[] embeddedBytes = CommonUtil.gzipDecompress(
                Base64Utils.decodeBase64(embeddedProxyHttp(shellBytes)));
        assertEquals(targetJreVersion, new ClassReader(embeddedBytes).readUnsignedShort(6));
    }

    private static String embeddedProxyHttp(byte[] shellBytes) {
        final String[] value = new String[1];
        new ClassReader(shellBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object constantValue) {
                if ("proxyHttpGZipBase64".equals(name)) {
                    value[0] = (String) constantValue;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE);
        assertNotNull(value[0], "generated Dubbo service must embed ProxyHttp");
        return value[0];
    }
}
