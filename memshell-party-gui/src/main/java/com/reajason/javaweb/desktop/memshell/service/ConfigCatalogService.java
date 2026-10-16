package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.Packers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 进程内配置目录，替代 web 端的 /api/config、/api/config/packers/tree、/api/config/command/configs。
 */
public class ConfigCatalogService {

    public static class ConfigCatalog {
        private final Map<String, Map<String, List<String>>> core;
        private final Map<String, List<String>> customShellTypes;
        private final List<PackerCategory> packers;
        private final List<String> commandEncryptors;
        private final List<String> commandImplementationClasses;

        public ConfigCatalog(Map<String, Map<String, List<String>>> core,
                             Map<String, List<String>> customShellTypes,
                             List<PackerCategory> packers,
                             List<String> commandEncryptors,
                             List<String> commandImplementationClasses) {
            this.core = core;
            this.customShellTypes = customShellTypes;
            this.packers = packers;
            this.commandEncryptors = commandEncryptors;
            this.commandImplementationClasses = commandImplementationClasses;
        }

        public Map<String, Map<String, List<String>>> getCore() {
            return core;
        }

        public Map<String, List<String>> getCustomShellTypes() {
            return customShellTypes;
        }

        public List<PackerCategory> getPackers() {
            return packers;
        }

        public List<String> getCommandEncryptors() {
            return commandEncryptors;
        }

        public List<String> getCommandImplementationClasses() {
            return commandImplementationClasses;
        }
    }

    public ConfigCatalog load() {
        Map<String, Map<String, List<String>>> core = new LinkedHashMap<String, Map<String, List<String>>>();
        Map<String, List<String>> customShellTypes = new LinkedHashMap<String, List<String>>();

        for (String serverName : ServerFactory.getSupportedServers()) {
            AbstractServer server = ServerFactory.getServer(serverName);
            if (server == null) {
                continue;
            }
            customShellTypes.put(serverName, new ArrayList<String>(server.getShellInjectorMapping().getSupportedShellTypes()));

            Map<String, List<String>> toolMap = new LinkedHashMap<String, List<String>>();
            for (String tool : server.getSupportedShellTools()) {
                List<String> types = new ArrayList<String>(server.getSupportedShellTypes(tool));
                if (!types.isEmpty()) {
                    toolMap.put(tool, types);
                }
            }
            core.put(serverName, toolMap);
        }

        List<PackerCategory> packers = new ArrayList<PackerCategory>();
        for (Packers root : Packers.values()) {
            if (root.getParentPacker() != null) {
                continue;
            }
            List<Packers> children = Packers.getPackersWithParent(root.getInstance().getClass());
            List<String> childNames = new ArrayList<String>();
            for (Packers child : children) {
                childNames.add(child.name());
            }
            packers.add(new PackerCategory(root.name(), childNames));
        }

        List<String> encryptors = new ArrayList<String>();
        for (CommandConfig.Encryptor encryptor : CommandConfig.Encryptor.values()) {
            encryptors.add(encryptor.name());
        }
        List<String> impls = new ArrayList<String>();
        for (CommandConfig.ImplementationClass impl : CommandConfig.ImplementationClass.values()) {
            impls.add(impl.name());
        }

        return new ConfigCatalog(core, customShellTypes, packers, encryptors, impls);
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
