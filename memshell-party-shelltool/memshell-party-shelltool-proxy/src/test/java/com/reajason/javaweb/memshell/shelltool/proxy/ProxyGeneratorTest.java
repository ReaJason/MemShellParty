package com.reajason.javaweb.memshell.shelltool.proxy;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.server.jetty.Jetty;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

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

    @Test
    void strutsActionIsNotAClassLoader() {
        ProxyConfig config = ProxyConfig.builder()
                .shellTemplateClassName(ProxyStruts2Action.class.getName())
                .shellClassName("com.opensymphony.xwork2.GeneratedProxyAction")
                .build();
        byte[] shellBytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.Struts2)
                .shellType(ShellType.ACTION)
                .build(), config).getBytes();

        assertEquals("java/lang/Object", new ClassReader(shellBytes).getSuperName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"6", "7+"})
    void oldJettyHandlersDoNotRetainVersionSpecificFieldTypes(String serverVersion) {
        ProxyConfig toolConfig = ProxyConfig.builder()
                .shellTemplateClassName(ProxyJettyHandler.class.getName())
                .shellClassName("org.eclipse.jetty.server.GeneratedProxyHandler")
                .build();
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .shellType(ShellType.HANDLER)
                .serverVersion(serverVersion)
                .build();
        byte[] shellBytes = new ProxyGenerator(shellConfig, toolConfig).getBytes();
        shellBytes = new Jetty().postProcessShellBytes(
                shellBytes, shellConfig, toolConfig, InjectorConfig.builder().build());

        Map<String, String> fields = new HashMap<>();
        new ClassReader(shellBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object constantValue) {
                fields.put(name, descriptor);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        for (String name : new String[]{"nextHandler", "jettyRequest", "jettyResponse", "jettyCallback"}) {
            assertEquals("Ljava/lang/Object;", fields.get(name), name);
        }
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
