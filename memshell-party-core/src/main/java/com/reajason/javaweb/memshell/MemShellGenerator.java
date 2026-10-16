package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import com.reajason.javaweb.utils.tuple.Pair;
import net.bytebuddy.jar.asm.Opcodes;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

        injectorConfig.setInjectorTemplateClassName(injectorTemplateClassName);
        injectorConfig.setInjectorTemplateClassLoader(server.getClass().getClassLoader());
        injectorConfig.setShellClassName(shellToolConfig.getShellClassName());
        injectorConfig.setShellClassBytes(shellBytes);

        InjectorGenerator injectorGenerator = new InjectorGenerator(shellConfig, injectorConfig);
        byte[] injectorBytes = injectorGenerator.generate();
        if (shellConfig.isProbe() && !shellConfig.getShellType().startsWith(ShellType.AGENT)) {
            ProbeConfig probeConfig = ProbeConfig.builder()
                    .shellClassName(injectorConfig.getInjectorClassName() + "Wrapper")
                    .probeMethod(ProbeMethod.ResponseBody)
                    .probeContent(ProbeContent.Bytecode)
                    .targetJreVersion(shellConfig.getTargetJreVersion())
                    .byPassJavaModule(shellConfig.isByPassJavaModule())
                    .shrink(shellConfig.isShrink())
                    .debug(shellConfig.isDebug())
                    .staticInitialize(injectorConfig.isStaticInitialize())
                    .build();
            ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                    .server(serverName)
                    .base64Bytes(Base64Utils.encodeBase64String(CommonUtil.gzipCompress(injectorBytes)))
                    .build();
            injectorBytes = new ResponseBodyGenerator(probeConfig, responseBodyConfig).getBytes();
            injectorConfig.setInjectorClassName(probeConfig.getShellClassName());
        }

        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();

        return MemShellResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellBytes(shellBytes)
                .injectorClassName(injectorConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .injectorInnerClassBytes(innerClassBytes)
                .build();
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
