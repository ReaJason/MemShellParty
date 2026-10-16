package com.reajason.javaweb.memshell;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.custom.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.CustomShellGenerator;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ServerMeta;
import com.reajason.javaweb.memshell.spi.ServerProvider;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * SPI-based discovery and registration for servers and shell tools.
 * <p>
 * 单例：通过 {@link #getInstance()} 获取。查询与生成服务一般不直接用这里，
 * 走 {@link MemShellGenerator} 门面；扩展（自定义 server/tool、测试注册）才需要碰这个类。
 *
 * @author ReaJason
 * @since 3.0.0
 */
public class MemShellRegistry {
    private static final MemShellRegistry INSTANCE = new MemShellRegistry();

    private final Map<String, AbstractServer> serverInstances = new ConcurrentHashMap<>();
    private final Map<String, Supplier<AbstractServer>> serverSuppliers = new ConcurrentHashMap<>();
    private final List<String> supportedServers = new CopyOnWriteArrayList<>();

    private final Map<String, ShellToolProvider> toolProviders = new ConcurrentHashMap<>();
    private final List<String> supportedTools = new CopyOnWriteArrayList<>();

    private volatile boolean initialized = false;

    private MemShellRegistry() {
    }

    public static MemShellRegistry getInstance() {
        return INSTANCE;
    }

    public synchronized void init() {
        if (initialized) {
            return;
        }
        // 先置位再注册：registerServer/registerTool 会回调 getServer/addToolMapping，
        // 若等过程结束才置位，这些回调会逐层重入 init()
        initialized = true;

        // Register built-in Custom tool (raw class bytes escape hatch, not an SPI plugin)
        registerTool(ShellTool.Custom, new ShellToolProvider() {
            @Override
            public ToolMapping getToolMapping() {
                return ToolMapping.builder().build();
            }

            @Override
            public Class<? extends ShellToolConfig> getConfigClass() {
                return CustomConfig.class;
            }

            @Override
            public Class<? extends ShellGenerator> getGeneratorClass() {
                return CustomShellGenerator.class;
            }
        });

        // Discover server providers via SPI
        List<ServerProvider> discoveredServers = new ArrayList<>();
        for (ServerProvider provider : ServiceLoader.load(ServerProvider.class)) {
            discoveredServers.add(provider);
        }
        discoveredServers.sort(Comparator.comparingInt(p -> {
            ServerMeta meta = p.getClass().getAnnotation(ServerMeta.class);
            return meta != null ? meta.order() : 1000;
        }));
        for (ServerProvider provider : discoveredServers) {
            ServerMeta meta = provider.getClass().getAnnotation(ServerMeta.class);
            String name = meta != null ? meta.name() : provider.getClass().getSimpleName();
            registerServer(name, provider::createServer);
        }

        // Discover shell tool providers via SPI
        List<ShellToolProvider> discoveredTools = new ArrayList<>();
        for (ShellToolProvider provider : ServiceLoader.load(ShellToolProvider.class)) {
            discoveredTools.add(provider);
        }
        discoveredTools.sort(Comparator.comparingInt(p -> {
            ShellToolMeta meta = p.getClass().getAnnotation(ShellToolMeta.class);
            return meta != null ? meta.order() : 1000;
        }));
        for (ShellToolProvider provider : discoveredTools) {
            ShellToolMeta meta = provider.getClass().getAnnotation(ShellToolMeta.class);
            String name = meta != null ? meta.name() : provider.getClass().getSimpleName();
            registerTool(name, provider);
        }
    }

    public void registerServer(String serverName, Supplier<AbstractServer> supplier) {
        if (serverName == null || serverName.trim().isEmpty()) {
            throw new IllegalArgumentException("Server name cannot be null or empty.");
        }
        Supplier<AbstractServer> existing = serverSuppliers.putIfAbsent(serverName, supplier);
        if (existing == null) {
            supportedServers.add(serverName);
            // Wire existing tools to this new server
            AbstractServer server = getServer(serverName);
            if (server != null) {
                wireToolsToServer(server);
            }
        }
    }

    public void registerTool(String toolName, ShellToolProvider provider) {
        if (toolName == null || toolName.trim().isEmpty()) {
            throw new IllegalArgumentException("ShellTool name cannot be null or empty.");
        }
        if (!toolProviders.containsKey(toolName)) {
            toolProviders.put(toolName, provider);
            supportedTools.add(toolName);
            addToolMapping(toolName, provider.getToolMapping());
        }
    }

    public AbstractServer getServer(String serverName) {
        init();
        if (serverName == null) {
            return null;
        }
        return serverInstances.computeIfAbsent(serverName, k -> {
            Supplier<AbstractServer> supplier = serverSuppliers.get(k);
            if (supplier == null) {
                return null;
            }
            AbstractServer server = supplier.get();
            wireToolsToServer(server);
            return server;
        });
    }

    public List<String> getSupportedServers() {
        init();
        return Collections.unmodifiableList(supportedServers);
    }

    public List<String> getSupportedTools() {
        init();
        return Collections.unmodifiableList(supportedTools);
    }

    /**
     * @return 该工具的 provider；没注册过（含 {@code toolName} 为 null，如界面上的工具没选）返回 null
     */
    public ShellToolProvider getToolProvider(String toolName) {
        init();
        // ConcurrentHashMap 不接受 null 键，这里挡一道，让调用方拿到 null 而不是 NPE
        return toolName == null ? null : toolProviders.get(toolName);
    }

    /**
     * Add (or replace) one tool's shell mappings on every registered server.
     * <p>
     * Order-independent: servers are created on demand via {@link #getServer(String)}, so a call
     * made before any server was instantiated has the same effect as one made after. The tool
     * itself must be registered first ({@link #registerTool}), otherwise the servers would
     * advertise a tool that cannot generate.
     */
    public void addToolMapping(String shellTool, ToolMapping toolMapping) {
        if (toolMapping == null) {
            return;
        }
        if (!toolProviders.containsKey(shellTool)) {
            throw new IllegalArgumentException("Unsupported shell tool: " + shellTool + ", register it before adding mappings.");
        }
        Map<String, String> rawToolMapping = toolMapping.getShellClassMap();
        for (String supportedServer : supportedServers) {
            AbstractServer server = getServer(supportedServer);
            if (server != null) {
                applyToolMappingToServer(server, shellTool, rawToolMapping);
            }
        }
    }

    /**
     * Wire every registered tool to a server, in {@link ShellToolMeta#order()} (registration)
     * order so the tool list the UI shows stays stable.
     */
    private void wireToolsToServer(AbstractServer server) {
        for (String toolName : supportedTools) {
            ShellToolProvider provider = toolProviders.get(toolName);
            if (provider == null) {
                continue;
            }
            ToolMapping toolMapping = provider.getToolMapping();
            if (toolMapping != null) {
                applyToolMappingToServer(server, toolName, toolMapping.getShellClassMap());
            }
        }
    }

    private void applyToolMappingToServer(AbstractServer server, String shellTool, Map<String, String> rawToolMapping) {
        InjectorMapping injectorMapping = server.getShellInjectorMapping();
        if (injectorMapping == null) {
            return;
        }
        Set<String> supportedShellTypes = injectorMapping.getSupportedShellTypes();
        ToolMapping.ToolMappingBuilder builder = ToolMapping.builder();
        for (String shellType : supportedShellTypes) {
            String shellClassName = rawToolMapping.get(shellType);
            if (shellClassName != null) {
                builder.addShellClass(shellType, shellClassName);
            }
        }
        ToolMapping mapping = builder.build();
        if (mapping.isNotEmpty()) {
            server.addToolMapping(shellTool, mapping);
        }
    }
}
