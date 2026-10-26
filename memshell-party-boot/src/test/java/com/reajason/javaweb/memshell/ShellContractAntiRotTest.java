package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.memshell.server.AbstractServer;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 契约防腐测试：每个 server 通过 {@link AbstractServer#getShellMethodContracts} 声明的
 * 方法契约，凡真实存在于未混淆 shell 类中的，混淆后必须仍然存活；注入器契约同理。
 * 默认的 {@link MethodContracts#CONSERVATIVE} 兜底集合跳过（它是广谱黑名单而非 server 声明）。
 * <p>
 * 契约集合是防御性超集（如 FILTER_CONTRACTS 含 init/destroy，但具体模板未必覆写），
 * 因此存在性断言取交集而非全量；另设全局存活计数下限防止契约整体失效（如批量拼错方法名）。
 * 同一 server 对多个 shellType 返回同一契约集合时，普通 shell 与 Agent shell 各取一个代表
 * 混淆一次，避免 Agent 壳（入口是 equals）把真实容器入口的校验挤掉。
 */
class ShellContractAntiRotTest {

    @Test
    void runtimeEntryContractsCannotRot() {
        assertContains(MethodContracts.VALVE_CONTRACTS,
                "invoke", "getNext", "setNext", "isAsyncSupported", "backgroundProcess");
        assertContains(MethodContracts.UPGRADE_CONTRACTS,
                "accept", "getHttpUpgradeName", "getAlpnIdentifier", "getAlpnName",
                "getProcessor", "getInternalUpgradeHandler");
        assertContains(MethodContracts.DUBBO_CONTRACTS, "handle");
        assertContains(MethodContracts.INJECTOR_COMMON,
                "transform", "initChannel", "onChannelInit", "invoke");
        assertContains(MethodContracts.FILTER_CONTRACTS, "equals");
        assertContains(MethodContracts.WEBSOCKET_CONTRACTS,
                "onOpen", "onClose", "onMessage", "modifyHandshake");
        assertContains(MethodContracts.RAW_WEBSOCKET_CONTRACTS,
                "doFilter", "init", "destroy",
                "onStart", "onReadBinary", "onReadText", "onDisconnect");
        assertContains(MethodContracts.JETTY_HANDLER_CONTRACTS, "equals");
        assertContains(MethodContracts.UNDERTOW_HANDLER_CONTRACTS, "equals");
    }

    private static void assertContains(Set<MethodSignature> contracts, String... names) {
        Set<String> actual = new LinkedHashSet<>();
        for (MethodSignature sig : contracts) {
            actual.add(sig.getName());
        }
        for (String name : names) {
            assertTrue(actual.contains(name), "missing runtime entry contract: " + name + " in " + actual);
        }
    }

    @Test
    void knownRuntimeEntriesSurviveObfuscation() {
        // shell 入口
        assertShellMethodSurvives("Tomcat", "Command", "AgentFilterChain", "equals");
        assertShellMethodSurvives("Tomcat", "Command", "Upgrade",
                "accept", "getHttpUpgradeName", "getAlpnIdentifier", "getAlpnName",
                "getProcessor", "getInternalUpgradeHandler");
        // WebSocket 的壳是 JSR-356 Endpoint；端点回调改名后容器会 AbstractMethodError
        assertShellMethodSurvives("Tomcat", "Command", "WebSocket", "onOpen", "onMessage");
        assertShellMethodSurvives("Tomcat", "Command", "JakartaWebSocket", "onOpen", "onMessage");
        // RawWebSocket 的壳是 Filter，helper 按名回调 onStart/onReadText 等入口，改名会断链
        assertShellMethodSurvives("Tomcat", "Command", "RawWebSocket", "doFilter", "init", "onStart", "onReadText");
        assertShellMethodSurvives("Tomcat", "Command", "JakartaRawWebSocket", "doFilter", "init", "onStart", "onReadText");
        assertShellMethodSurvives("Dubbo", "Command", "ApacheDubboService", "handle");
        assertShellMethodSurvives("TongWeb", "Command", "Valve",
                "invoke", "isAsyncSupported", "backgroundProcess");
        assertShellMethodSurvives("BES", "Command", "Valve",
                "invoke", "isAsyncSupported", "backgroundProcess");
        // 注入器容器回调
        assertInjectorMethodSurvives(Server.XXLJOB, "Command", "NettyHandler", "initChannel");
        assertInjectorMethodSurvives("SpringWebFlux", "Command", "NettyHandler", "onChannelInit");
        assertInjectorMethodSurvives("Tomcat", "Command", "ProxyValve", "invoke");
    }

    private static void assertShellMethodSurvives(String server, String shellTool, String shellType,
                                                  String... methodNames) {
        MemShellResult result = generate(new MemShellGenerator(), server, shellTool, shellType, true);
        Set<String> actual = methodNames(result.getShellBytes());
        for (String methodName : methodNames) {
            assertTrue(actual.contains(methodName),
                    server + "/" + shellType + " shell lost " + methodName + " after obfuscation: " + actual);
        }
    }

    private static void assertInjectorMethodSurvives(String server, String shellTool, String shellType,
                                                     String... methodNames) {
        MemShellResult result = generate(new MemShellGenerator(), server, shellTool, shellType, true);
        Set<String> actual = methodNames(result.getInjectorBytes());
        for (String methodName : methodNames) {
            assertTrue(actual.contains(methodName),
                    server + "/" + shellType + " injector lost " + methodName + " after obfuscation: " + actual);
        }
    }

    /**
     * 字段契约防腐：注入器按名反射读写的 shell 字段，凡在未混淆 shell 中真实存在的，
     * 混淆后必须仍然存在。class-obf 无字段黑名单，实现上通过关闭字段名混淆保证。
     */
    @Test
    void declaredFieldContractsSurviveObfuscation() {
        MemShellGenerator generator = new MemShellGenerator();
        List<String> failures = new ArrayList<>();
        List<String> covered = new ArrayList<>();
        for (String serverName : generator.getSupportedServers()) {
            AbstractServer server = generator.getServer(serverName);
            if (server == null) {
                continue;
            }
            for (String shellTool : new TreeSet<>(server.getSupportedShellTools())) {
                for (String shellType : new TreeSet<>(server.getSupportedShellTypes(shellTool))) {
                    Set<String> contracts = server.getShellFieldContracts(shellType);
                    if (contracts == null || contracts.isEmpty()) {
                        continue;
                    }
                    String label = serverName + " / " + shellTool + " / " + shellType;
                    covered.add(label);
                    try {
                        Set<String> originFields = fieldNames(generate(generator, serverName, shellTool,
                                shellType, false).getShellBytes());
                        Set<String> present = new LinkedHashSet<>();
                        for (String name : contracts) {
                            if (originFields.contains(name)) {
                                present.add(name);
                            }
                        }
                        if (present.isEmpty()) {
                            failures.add(label + " 字段契约与真实 shell 无交集: " + contracts);
                            continue;
                        }
                        Set<String> obfuscatedFields = fieldNames(generate(generator, serverName, shellTool,
                                shellType, true).getShellBytes());
                        for (String name : present) {
                            if (!obfuscatedFields.contains(name)) {
                                failures.add(label + " shell 契约字段 " + name + " 混淆后丢失: " + obfuscatedFields);
                            }
                        }
                    } catch (Throwable e) {
                        failures.add(label + " 生成失败 -> " + e);
                    }
                }
            }
        }
        assertFalse(covered.isEmpty(), "no server declared shell field contracts");
        assertEquals(Collections.emptyList(), failures, "field contract names lost after obfuscation");
    }

    @Test
    void declaredContractsExistInShellAndSurviveObfuscation() {
        MemShellGenerator memShellGenerator = new MemShellGenerator();
        List<String> failures = new ArrayList<>();
        List<String> covered = new ArrayList<>();
        int protectedCount = 0;
        for (String serverName : memShellGenerator.getSupportedServers()) {
            AbstractServer server = memShellGenerator.getServer(serverName);
            if (server == null) {
                continue;
            }
            // 契约集合去重：普通 shell 与 Agent shell 分开取代表
            Map<Set<MethodSignature>, Map<Boolean, String[]>> representatives = new IdentityHashMap<>();
            for (String shellTool : new TreeSet<>(server.getSupportedShellTools())) {
                for (String shellType : new TreeSet<>(server.getSupportedShellTypes(shellTool))) {
                    Set<MethodSignature> contracts = server.getShellMethodContracts(shellType);
                    if (contracts == null || contracts.isEmpty() || contracts == MethodContracts.CONSERVATIVE) {
                        continue;
                    }
                    boolean agent = shellType.startsWith(ShellType.AGENT);
                    representatives.computeIfAbsent(contracts, k -> new java.util.LinkedHashMap<>())
                            .putIfAbsent(agent, new String[]{shellTool, shellType});
                }
            }
            for (Map.Entry<Set<MethodSignature>, Map<Boolean, String[]>> group : representatives.entrySet()) {
                for (Map.Entry<Boolean, String[]> entry : group.getValue().entrySet()) {
                    Set<MethodSignature> contracts = group.getKey();
                    String shellTool = entry.getValue()[0];
                    String shellType = entry.getValue()[1];
                    String label = serverName + " / " + shellTool + " / " + shellType
                            + (entry.getKey() ? " (agent)" : "");
                    covered.add(label);
                    protectedCount += checkCombination(memShellGenerator, server, serverName, shellTool, shellType,
                            contracts, label, failures);
                }
            }
        }
        assertTrue(covered.size() > 10, "should cover many server contract sets, got " + covered.size());
        assertTrue(protectedCount > 30,
                "contract sets rotted away: almost no declared contract method exists in real shells, count=" + protectedCount);
        assertEquals(Collections.emptyList(), failures, "contract names lost after obfuscation");
    }

    private static int checkCombination(MemShellGenerator generator, AbstractServer server,
                                         String serverName, String shellTool, String shellType,
                                         Set<MethodSignature> contracts, String label,
                                         List<String> failures) {
        try {
            MemShellResult origin = generate(generator, serverName, shellTool, shellType, false);
            Set<String> presentContracts = presentContractNames(contracts, origin.getShellBytes());
            if (presentContracts.isEmpty()) {
                failures.add(label + " 契约集合与真实 shell 无交集: " + contractNames(contracts));
                return 0;
            }

            Set<MethodSignature> injectorContracts = server.getInjectorMethodContracts(shellType);
            Set<String> presentInjectorContracts = presentContractNames(injectorContracts, origin.getInjectorBytes());

            MemShellResult obfuscated = generate(generator, serverName, shellTool, shellType, true);
            Set<String> obfMethods = methodNames(obfuscated.getShellBytes());
            for (String name : presentContracts) {
                if (!obfMethods.contains(name)) {
                    failures.add(label + " shell 契约方法 " + name + " 混淆后丢失: " + obfMethods);
                }
            }

            Set<String> obfInjectorMethods = methodNames(obfuscated.getInjectorBytes());
            for (String name : presentInjectorContracts) {
                if (!obfInjectorMethods.contains(name)) {
                    failures.add(label + " injector 契约方法 " + name + " 混淆后丢失: " + obfInjectorMethods);
                }
            }

            if (obfuscated.getObfuscationInfo() == null
                    || !obfuscated.getObfuscationInfo().isEnabled()) {
                failures.add(label + " 混淆结果缺少 obfuscationInfo 元数据");
            }
            return presentContracts.size();
        } catch (Throwable e) {
            failures.add(label + " 生成失败 -> " + e);
            return 0;
        }
    }

    private static MemShellResult generate(MemShellGenerator generator, String serverName,
                                           String shellTool, String shellType, boolean obfuscate) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(serverName)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJreVersionFor(serverName))
                .serverVersion(serverVersionFor(serverName, shellType))
                .obfuscation(obfuscate ? ObfuscationConfig.enabled() : ObfuscationConfig.defaults())
                .build();
        return generator.generate(shellConfig, InjectorConfig.builder()
                .urlPattern(shellType.endsWith(ShellType.RAW_WEBSOCKET) ? "/raw-ws" : "/*")
                .build(), Collections.emptyMap());
    }

    private static Set<String> presentContractNames(Set<MethodSignature> contracts, byte[] classBytes) {
        Set<String> methodNames = methodNames(classBytes);
        Set<String> present = new LinkedHashSet<>();
        for (MethodSignature sig : contracts) {
            if (methodNames.contains(sig.getName())) {
                present.add(sig.getName());
            }
        }
        return present;
    }

    private static String contractNames(Set<MethodSignature> contracts) {
        Set<String> names = new LinkedHashSet<>();
        for (MethodSignature sig : contracts) {
            names.add(sig.getName());
        }
        return names.toString();
    }

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

    private static Set<String> fieldNames(byte[] classBytes) {
        Set<String> names = new LinkedHashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public org.objectweb.asm.FieldVisitor visitField(int access, String name, String descriptor,
                                                             String signature, Object value) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return names;
    }

    private static int targetJreVersionFor(String serverName) {
        if (Server.SpringWebFlux.equals(serverName)
                || Server.XXLJOB.equals(serverName)
                || Server.Dubbo.equals(serverName)) {
            return Opcodes.V1_8;
        }
        return Opcodes.V1_6;
    }

    private static String serverVersionFor(String serverName, String shellType) {
        if (Server.Jetty.equals(serverName)
                && (ShellType.HANDLER.equals(shellType) || ShellType.JAKARTA_HANDLER.equals(shellType))) {
            return "7+";
        }
        if (Server.TongWeb.equals(serverName)
                && (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType))) {
            return "8";
        }
        return null;
    }
}
