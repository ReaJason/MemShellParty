package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.PackerCategory;
import com.reajason.javaweb.packer.Packers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 进程内配置目录，替代 web 端的 /api/config、/api/config/packers/tree、/api/config/shelltool/configs。
 */
public class ConfigCatalogService {

    private final MemShellGenerator memShellGenerator = new MemShellGenerator();

    public static class ConfigCatalog {
        private final MemShellGenerator.ShellTypeCatalog shellTypeCatalog;
        private final Map<String, List<String>> customShellTypes;
        private final List<PackerCategory> packers;
        private final List<ToolConfigFactory.ToolConfigDescriptor> shellToolConfigs;

        public ConfigCatalog(MemShellGenerator.ShellTypeCatalog shellTypeCatalog,
                             Map<String, List<String>> customShellTypes,
                             List<PackerCategory> packers,
                             List<ToolConfigFactory.ToolConfigDescriptor> shellToolConfigs) {
            this.shellTypeCatalog = shellTypeCatalog;
            this.customShellTypes = customShellTypes;
            this.packers = packers;
            this.shellToolConfigs = shellToolConfigs;
        }

        /**
         * 服务端 / 工具 / 类型的支持矩阵，按轴查询走它（{@code getServers()} / {@code getShellTools(server)} /
         * {@code getShellTypes(server, tool)}），要整张表时用 {@code asMap()}。
         */
        public MemShellGenerator.ShellTypeCatalog getShellTypeCatalog() {
            return shellTypeCatalog;
        }

        public Map<String, List<String>> getCustomShellTypes() {
            return customShellTypes;
        }

        public List<PackerCategory> getPackers() {
            return packers;
        }

        /**
         * 每个工具的 {@code @ConfigField} 参数，顺序即表单顺序（web 端 /api/config/shelltool/configs 同源）。
         */
        public List<ToolConfigFactory.ToolConfigDescriptor> getShellToolConfigs() {
            return shellToolConfigs;
        }

        /**
         * 某工具某个参数的可选值：只有枚举型参数有；参数不存在或不是枚举时返回空表。
         */
        public List<String> getParamOptions(String tool, String paramName) {
            for (ToolConfigFactory.ToolConfigDescriptor descriptor : shellToolConfigs) {
                if (!descriptor.getTool().equals(tool)) {
                    continue;
                }
                for (ToolConfigFactory.ConfigParam param : descriptor.getParams()) {
                    if (param.getName().equals(paramName)) {
                        return param.getOptions();
                    }
                }
            }
            return Collections.emptyList();
        }
    }

    public ConfigCatalog load() {
        // 注册表快照只读一次：矩阵与各轴查询共用这一份，界面每次级联都重建一遍没必要
        MemShellGenerator.ShellTypeCatalog shellTypeCatalog = memShellGenerator.getShellTypeCatalog();
        Map<String, List<String>> customShellTypes = new LinkedHashMap<String, List<String>>();

        for (String serverName : memShellGenerator.getSupportedServers()) {
            AbstractServer server = memShellGenerator.getServer(serverName);
            if (server == null) {
                continue;
            }
            customShellTypes.put(serverName, new ArrayList<String>(server.getShellInjectorMapping().getSupportedShellTypes()));
        }

        List<PackerCategory> packers = Packers.getPackerTree();

        return new ConfigCatalog(shellTypeCatalog, customShellTypes, packers, ToolConfigFactory.describeAll());
    }

    /**
     * 对齐 web serverversion-field：TongWeb/Jetty 需要版本，其余 Unknown（Jetty5 精确匹配落 Unknown）。
     */
    public List<String> getServerVersionOptions(String server) {
        if ("TongWeb".equals(server)) {
            return Arrays.asList("6", "7", "8");
        }
        if ("Jetty".equals(server)) {
            return Arrays.asList("6", "7+", "12");
        }
        return Collections.singletonList("Unknown");
    }

    public List<String> getTargetJdkOptions() {
        return Arrays.asList("50", "52", "53", "55", "61", "65");
    }

    public String getTargetJdkLabel(String value) {
        if ("50".equals(value)) return "Java 6";
        if ("52".equals(value)) return "Java 8";
        if ("53".equals(value)) return "Java 9";
        if ("55".equals(value)) return "Java 11";
        if ("61".equals(value)) return "Java 17";
        if ("65".equals(value)) return "Java 21";
        return value;
    }
}
