package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.PackerCategoryModel;
import com.reajason.javaweb.desktop.memshell.model.PackerEntryModel;
import com.reajason.javaweb.desktop.memshell.model.PackerSchemaFieldModel;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.spec.PackerFieldSchema;
import com.reajason.javaweb.packer.spec.PackerOptionValue;
import com.reajason.javaweb.packer.spec.PackerSchema;

import java.util.*;
import java.util.stream.Collectors;

public class ConfigCatalogService {

    public static class ConfigCatalog {
        private final Map<String, List<String>> servers;
        private final Map<String, Map<String, List<String>>> core;
        private final List<PackerCategoryModel> packers;
        private final List<String> commandEncryptors;
        private final List<String> commandImplementationClasses;

        public ConfigCatalog(Map<String, List<String>> servers,
                             Map<String, Map<String, List<String>>> core,
                             List<PackerCategoryModel> packers,
                             List<String> commandEncryptors,
                             List<String> commandImplementationClasses) {
            this.servers = servers;
            this.core = core;
            this.packers = packers;
            this.commandEncryptors = commandEncryptors;
            this.commandImplementationClasses = commandImplementationClasses;
        }

        public Map<String, List<String>> getServers() { return servers; }
        public Map<String, Map<String, List<String>>> getCore() { return core; }
        public List<PackerCategoryModel> getPackers() { return packers; }
        public List<String> getCommandEncryptors() { return commandEncryptors; }
        public List<String> getCommandImplementationClasses() { return commandImplementationClasses; }
    }

    public ConfigCatalog load() {
        Map<String, List<String>> servers = new LinkedHashMap<>();
        Map<String, Map<String, List<String>>> core = new LinkedHashMap<>();

        for (String serverName : ServerFactory.getSupportedServers()) {
            AbstractServer server = ServerFactory.getServer(serverName);
            if (server == null) {
                continue;
            }
            List<String> shellTypes = new ArrayList<>(server.getShellInjectorMapping().getSupportedShellTypes());
            servers.put(serverName, shellTypes);

            Map<String, List<String>> toolMap = new LinkedHashMap<>();
            for (String tool : server.getSupportedShellTools()) {
                List<String> types = new ArrayList<>(server.getSupportedShellTypes(tool));
                if (!types.isEmpty()) {
                    toolMap.put(tool, types);
                }
            }
            core.put(serverName, toolMap);
        }

        List<PackerCategoryModel> packerModels = new ArrayList<>();
        for (Map.Entry<String, List<Packers>> entry : Packers.groupedPackers().entrySet()) {
            PackerCategoryModel category = new PackerCategoryModel(entry.getKey());
            for (Packers packerEnum : entry.getValue()) {
                PackerEntryModel p = new PackerEntryModel();
                p.setCategoryName(entry.getKey());
                p.setName(packerEnum.name());
                p.setOutputKind(packerEnum.getOutputKind());
                p.setCategoryAnchor(packerEnum.hasChildren());
                PackerSchema schema = packerEnum.getSchema();
                if (schema != null) {
                    p.getDefaultConfig().putAll(schema.getDefaultConfig());
                    for (PackerFieldSchema field : schema.getFields()) {
                        PackerSchemaFieldModel f = new PackerSchemaFieldModel();
                        f.setKey(field.getKey());
                        f.setType(field.getType() == null ? null : field.getType().name());
                        f.setRequired(field.isRequired());
                        f.setDefaultValue(field.getDefaultValue());
                        f.setDescription(field.getDescription());
                        f.setDescriptionI18nKey(field.getDescriptionI18nKey());
                        for (PackerOptionValue option : field.getOptions()) {
                            f.getOptions().add(new PackerSchemaFieldModel.Option(option.getValue(), option.getLabel()));
                        }
                        p.getFields().add(f);
                    }
                }
                category.getPackers().add(p);
            }
            packerModels.add(category);
        }

        List<String> encryptors = Arrays.stream(CommandConfig.Encryptor.values()).map(Enum::name).collect(Collectors.toList());
        List<String> impls = Arrays.stream(CommandConfig.ImplementationClass.values()).map(Enum::name).collect(Collectors.toList());

        return new ConfigCatalog(servers, core, packerModels, encryptors, impls);
    }

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
        if ("50".equals(value)) return "Java6";
        if ("52".equals(value)) return "Java8";
        if ("53".equals(value)) return "Java9";
        if ("55".equals(value)) return "Java11";
        if ("61".equals(value)) return "Java17";
        if ("65".equals(value)) return "Java21";
        return value;
    }
}
