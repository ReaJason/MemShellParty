package com.reajason.javaweb.packer.jar.agent;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.fileless.FilelessAgentBootstrap;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.GZIPOutputStream;

final class FilelessPayloadAssembler {
    private static final String RUNTIME_PACKAGE = "com.reajason.javaweb.fileless";
    private static final String RUNTIME_PACKAGE_PATH = RUNTIME_PACKAGE.replace('.', '/');
    private static final String BOOTSTRAP_CLASS = RUNTIME_PACKAGE + ".FilelessAgentBootstrap";
    private static final String PROVIDER_CLASS = RUNTIME_PACKAGE + ".InstrumentationProvider";
    private static final int PAYLOAD_MAGIC = 0x464c4131;
    private static final int CHUNK_LENGTH = 60000;

    byte[] assemble(byte[] agentJar) throws Exception {
        Map<String, byte[]> runtimeClasses = readRuntimeClasses();
        byte[] bootstrap = runtimeClasses.remove(BOOTSTRAP_CLASS);
        if (bootstrap == null) {
            throw new IOException("Missing " + BOOTSTRAP_CLASS);
        }
        String isolatedPackage = CommonUtil.generateRandomPackage();
        Map<String, byte[]> isolatedClasses = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : runtimeClasses.entrySet()) {
            isolatedClasses.put(entry.getKey().replace(RUNTIME_PACKAGE, isolatedPackage),
                    ClassRenameUtils.relocateClass(entry.getValue(), RUNTIME_PACKAGE, isolatedPackage));
        }
        byte[] bundle = bundle(isolatedClasses, agentJar);
        String[] chunks = chunks(Base64.getEncoder().encodeToString(bundle));
        byte[] isolatedBootstrap = ClassRenameUtils.relocateClass(bootstrap, RUNTIME_PACKAGE, isolatedPackage);
        return injectChunks(isolatedBootstrap, chunks);
    }

    private static Map<String, byte[]> readRuntimeClasses() throws Exception {
        return readRuntimeClasses(FilelessAgentBootstrap.class.getProtectionDomain().getCodeSource().getLocation());
    }

    static Map<String, byte[]> readRuntimeClasses(URL location) throws Exception {
        Map<String, byte[]> classes = new TreeMap<>();
        if ("jar".equals(location.getProtocol())) {
            JarURLConnection connection = (JarURLConnection) location.openConnection();
            connection.setUseCaches(false);
            try (JarFile jar = connection.getJarFile()) {
                readJar(jar, classes);
            }
        } else {
            File source = new File(location.toURI());
            if (source.isDirectory()) {
                File root = new File(source, RUNTIME_PACKAGE_PATH);
                readDirectory(root, root, classes);
            } else {
                try (JarFile jar = new JarFile(source)) {
                    readJar(jar, classes);
                }
            }
        }
        byte[] provider = classes.remove(PROVIDER_CLASS);
        if (provider == null) {
            throw new IOException("Missing fileless runtime classes at " + location);
        }
        Map<String, byte[]> ordered = new LinkedHashMap<>();
        ordered.put(PROVIDER_CLASS, provider);
        // JDK verification can resolve these helpers before the payload is fully defined.
        String[] jarLoaderClasses = {
                RUNTIME_PACKAGE + ".JarLoader$MemoryURLConnection",
                RUNTIME_PACKAGE + ".JarLoader$MemoryURLStreamHandler",
                RUNTIME_PACKAGE + ".JarLoader"
        };
        for (String className : jarLoaderClasses) {
            byte[] runtimeClass = classes.remove(className);
            if (runtimeClass == null) {
                throw new IOException("Missing " + className + " at " + location);
            }
            ordered.put(className, runtimeClass);
        }
        ordered.putAll(classes);
        return ordered;
    }

    private static void readDirectory(File root, File directory, Map<String, byte[]> classes) throws IOException {
        File[] files = directory.listFiles();
        if (files == null) {
            throw new IOException("Cannot list " + directory);
        }
        for (File file : files) {
            if (file.isDirectory()) {
                readDirectory(root, file, classes);
            } else if (file.getName().endsWith(".class")) {
                String relative = root.toURI().relativize(file.toURI()).getPath();
                String className = RUNTIME_PACKAGE + "." + relative.replace('/', '.').replaceAll("\\.class$", "");
                classes.put(className, Files.readAllBytes(file.toPath()));
            }
        }
    }

    private static void readJar(JarFile jar, Map<String, byte[]> classes) throws IOException {
        java.util.Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();
            if (entry.isDirectory() || !name.startsWith(RUNTIME_PACKAGE_PATH + "/") || !name.endsWith(".class")) {
                continue;
            }
            try (InputStream input = jar.getInputStream(entry)) {
                classes.put(name.substring(0, name.length() - 6).replace('/', '.'), IOUtils.toByteArray(input));
            }
        }
    }

    private static byte[] bundle(Map<String, byte[]> classes, byte[] agentJar) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(new GZIPOutputStream(output))) {
            data.writeInt(PAYLOAD_MAGIC);
            data.writeInt(classes.size());
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                data.writeUTF(entry.getKey());
                data.writeInt(entry.getValue().length);
                data.write(entry.getValue());
            }
            data.writeInt(agentJar.length);
            data.write(agentJar);
        }
        return output.toByteArray();
    }

    private static String[] chunks(String base64) {
        List<String> chunks = new ArrayList<>();
        for (int offset = 0; offset < base64.length(); offset += CHUNK_LENGTH) {
            chunks.add(base64.substring(offset, Math.min(base64.length(), offset + CHUNK_LENGTH)));
        }
        return chunks.toArray(new String[0]);
    }

    private static byte[] injectChunks(byte[] classBytes, String[] chunks) {
        ClassReader reader = new ClassReader(classBytes);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if ("payloadChunks".equals(name) && "()[Ljava/lang/String;".equals(descriptor)) {
                    MethodVisitor method = super.visitMethod(access, name, descriptor, signature, exceptions);
                    writePayloadMethod(method, chunks);
                    return null;
                }
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
        };
        reader.accept(visitor, 0);
        return writer.toByteArray();
    }

    private static void writePayloadMethod(MethodVisitor method, String[] chunks) {
        method.visitCode();
        pushInt(method, chunks.length);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        for (int i = 0; i < chunks.length; i++) {
            method.visitInsn(Opcodes.DUP);
            pushInt(method, i);
            method.visitLdcInsn(chunks[i]);
            method.visitInsn(Opcodes.AASTORE);
        }
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
    }

    private static void pushInt(MethodVisitor method, int value) {
        if (value <= Byte.MAX_VALUE) {
            method.visitIntInsn(Opcodes.BIPUSH, value);
        } else if (value <= Short.MAX_VALUE) {
            method.visitIntInsn(Opcodes.SIPUSH, value);
        } else {
            method.visitLdcInsn(value);
        }
    }
}
