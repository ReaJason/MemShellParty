package com.reajason.javaweb.packer.jar.agent;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Builds the standalone Windows fixture from the same packed bootstrap delivered to users. */
public final class WindowsPackedFixtureGenerator {
    private static final String PACKAGE = "com.reajason.javaweb.fileless.";
    private static final String AGENT = PACKAGE + "WindowsPackedAgentFixture";

    private WindowsPackedFixtureGenerator() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Required arguments: native-fixture.jar output.jar");
        }
        JarFile fixture = new JarFile(new File(args[0]));
        try {
            byte[] agent = read(fixture, AGENT);
            String shell = AGENT + "Shell";
            Map<String, byte[]> innerClasses = new LinkedHashMap<>();
            innerClasses.put(AGENT + "$TargetTransformer", read(fixture, AGENT + "$TargetTransformer"));
            innerClasses.put(AGENT + "$BootstrapLoader", read(fixture, AGENT + "$BootstrapLoader"));
            MemShellResult result = MemShellResult.builder()
                    .shellClassName(shell)
                    .shellBytes(ClassRenameUtils.renameClass(agent, shell))
                    .injectorClassName(AGENT)
                    .injectorBytes(agent)
                    .injectorInnerClassBytes(innerClasses)
                    .shellConfig(ShellConfig.builder().shellType(ShellType.AGENT).build())
                    .build();
            byte[] bootstrap = Base64.getDecoder().decode(new FilelessAgentPacker().pack(result));
            writeFixture(fixture, new File(args[1]), agent, innerClasses, bootstrap);
        } finally {
            fixture.close();
        }
    }

    private static void writeFixture(JarFile source, File output, byte[] agent,
                                     Map<String, byte[]> innerClasses, byte[] bootstrap) throws Exception {
        File parent = output.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("Could not create " + parent);
        }
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, AGENT);
        JarOutputStream jar = new JarOutputStream(new FileOutputStream(output), manifest);
        try {
            entry(jar, AGENT.replace('.', '/') + ".class", agent);
            for (Map.Entry<String, byte[]> inner : innerClasses.entrySet()) {
                entry(jar, inner.getKey().replace('.', '/') + ".class", inner.getValue());
            }
            entry(jar, (PACKAGE + "NativeAgentFixture$Target").replace('.', '/') + ".class",
                    read(source, PACKAGE + "NativeAgentFixture$Target"));
            entry(jar, (PACKAGE + "RetransformFixture").replace('.', '/') + ".class",
                    read(source, PACKAGE + "RetransformFixture"));
            entry(jar, "packed-bootstrap.class", bootstrap);
        } finally {
            jar.close();
        }
    }

    private static void entry(JarOutputStream jar, String name, byte[] bytes) throws IOException {
        jar.putNextEntry(new JarEntry(name));
        jar.write(bytes);
        jar.closeEntry();
    }

    private static byte[] read(JarFile jar, String className) throws IOException {
        JarEntry entry = jar.getJarEntry(className.replace('.', '/') + ".class");
        if (entry == null) {
            throw new IOException("Missing " + className);
        }
        InputStream input = jar.getInputStream(entry);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }
}
