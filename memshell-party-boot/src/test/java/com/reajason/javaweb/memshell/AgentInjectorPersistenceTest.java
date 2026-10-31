package com.reajason.javaweb.memshell;

import com.reajason.javaweb.agent.AgentInjectorSupport;
import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.injector.apusic.ApusicFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.jetty.JettyHandlerAgentInjector;
import com.reajason.javaweb.memshell.injector.resin.ResinFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.injector.undertow.UndertowServletHandlerAgentInjector;
import com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletContextAgentInjector;
import com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterChainAgentInjector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.*;

class AgentInjectorPersistenceTest {
    @TempDir
    Path tempDir;

    static Stream<Arguments> persistenceCases() {
        return Stream.of(
                Arguments.of(ApusicFilterChainAgentInjector.class, ShellType.AGENT_FILTER_CHAIN,
                        "com/apusic/web/container/FilterChainImpl", "performFilter"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/eclipse/jetty/servlet/ServletHandler", "doHandle"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/eclipse/jetty/ee8/servlet/ServletHandler", "doHandle"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/eclipse/jetty/ee9/servlet/ServletHandler", "doHandle"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/eclipse/jetty/ee10/servlet/ServletHandler$Chain", "doFilter"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/eclipse/jetty/ee11/servlet/ServletHandler$Chain", "doFilter"),
                Arguments.of(JettyHandlerAgentInjector.class, ShellType.JETTY_AGENT_HANDLER,
                        "org/mortbay/jetty/servlet/ServletHandler", "handle"),
                Arguments.of(ResinFilterChainAgentInjector.class, ShellType.AGENT_FILTER_CHAIN,
                        "com/caucho/server/http/FilterChainFilter", "doFilter"),
                Arguments.of(ResinFilterChainAgentInjector.class, ShellType.AGENT_FILTER_CHAIN,
                        "com/caucho/server/dispatch/FilterFilterChain", "doFilter"),
                Arguments.of(UndertowServletHandlerAgentInjector.class, ShellType.UNDERTOW_AGENT_SERVLET_HANDLER,
                        "io/undertow/servlet/handlers/ServletInitialHandler", "handleFirstRequest"),
                Arguments.of(WebLogicServletContextAgentInjector.class, ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT,
                        "weblogic/servlet/internal/WebAppServletContext", "securedExecute"),
                Arguments.of(WebSphereFilterChainAgentInjector.class, ShellType.WAS_AGENT_FILTER_MANAGER,
                        "com/ibm/ws/webcontainer/filter/WebAppFilterManager", "doFilter")
        );
    }

    @ParameterizedTest(name = "{2}.{3}")
    @MethodSource("persistenceCases")
    void generatedAgentPersistsIntoJarAndKeepsPristineBackup(Class<?> injectorTemplateClass, String shellType,
                                                              String targetInternalName,
                                                              String targetMethodName) throws Exception {
        String shellClassName = "test.GeneratedPersistedShell";
        String injectorClassName = "test.GeneratedPersistenceAgent";
        byte[] shellClassBytes = shellClass(shellClassName.replace('.', '/'));
        String jarName = "agent-persistence-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        Path agentJar = tempDir.resolve("agent-" + UUID.randomUUID() + ".jar");
        Path expectedBackup = Paths.get("/tmp").resolve(jarName + ".bak");
        try {
            writeJar(originalJar, targetInternalName + ".class", targetClass(targetInternalName, targetMethodName));
            assertTrue(originalJar.toFile().setLastModified(System.currentTimeMillis() - 60_000));
            long originalModified = Files.getLastModifiedTime(originalJar).toMillis();
            byte[] originalJarBytes = Files.readAllBytes(originalJar);
            writeGeneratedAgent(agentJar, injectorClassName, shellClassName, shellClassBytes,
                    shellType, injectorTemplateClass);
            try (JarFile generatedJar = new JarFile(agentJar.toFile())) {
                assertNotNull(generatedJar.getJarEntry(classEntry(AgentPersistence.class.getName())));
                assertNotNull(generatedJar.getJarEntry(classEntry(AgentPersistence.Transformer.class.getName())));
                assertNotNull(generatedJar.getJarEntry(classEntry(AgentInjectorSupport.class.getName())));
                assertNotNull(generatedJar.getJarEntry(classEntry(AgentInjectorSupport.Config.class.getName())));
            }

            Class<?> originalTargetClass;
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                originalTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = originalTargetClass.newInstance();
                originalTargetClass.getMethod(targetMethodName).invoke(target);
                assertTrue(originalTargetClass.getField("invoked").getBoolean(null));
            }

            assertEquals(expectedBackup.toFile(), invokePersist(agentJar, injectorClassName, originalTargetClass));
            assertTrue(Files.getLastModifiedTime(originalJar).toMillis() > originalModified,
                    "The persisted jar must have a fresh timestamp so module caches reload it");
            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
            byte[] persistedJarBytes = Files.readAllBytes(originalJar);
            assertFalse(Arrays.equals(originalJarBytes, persistedJarBytes));
            try (JarFile persistedJar = new JarFile(originalJar.toFile())) {
                assertArrayEquals(shellClassBytes, readEntry(persistedJar, classEntry(shellClassName)));
                assertArrayEquals("keep".getBytes("UTF-8"), readEntry(persistedJar, "application.txt"));
            }
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                Class<?> persistedTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = persistedTargetClass.newInstance();
                persistedTargetClass.getMethod(targetMethodName).invoke(target);
                assertFalse(persistedTargetClass.getField("invoked").getBoolean(null),
                        "The persisted hook should return before the original method body");
            }

            InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                    () -> invokePersist(agentJar, injectorClassName, originalTargetClass));
            assertTrue(failure.getCause() instanceof IllegalStateException);
            assertArrayEquals(persistedJarBytes, Files.readAllBytes(originalJar));
            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
        } finally {
            Files.deleteIfExists(expectedBackup);
        }
    }

    @ParameterizedTest(name = "{2}.{3}")
    @MethodSource("persistenceCases")
    void generatedAgentRestoresPersistedJarAndTransform(Class<?> injectorTemplateClass, String shellType,
                                                        String targetInternalName,
                                                        String targetMethodName) throws Exception {
        String shellClassName = "test.GeneratedRestoreShell";
        String injectorClassName = "test.GeneratedRestoreAgent";
        byte[] shellClassBytes = shellClass(shellClassName.replace('.', '/'));
        String jarName = "agent-restore-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        Path agentJar = tempDir.resolve("agent-" + UUID.randomUUID() + ".jar");
        Path expectedBackup = Paths.get("/tmp").resolve(jarName + ".bak");
        try {
            writeJar(originalJar, targetInternalName + ".class", targetClass(targetInternalName, targetMethodName));
            byte[] originalJarBytes = Files.readAllBytes(originalJar);
            writeGeneratedAgent(agentJar, injectorClassName, shellClassName, shellClassBytes,
                    shellType, injectorTemplateClass);
            Class<?> targetClass;
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                targetClass = loader.loadClass(targetInternalName.replace('/', '.'));
            }

            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{agentJar.toUri().toURL()},
                    AgentInjectorPersistenceTest.class.getClassLoader())) {
                Class<?> injectorClass = loader.loadClass(injectorClassName);
                Method launch = injectorClass.getDeclaredMethod("premain", String.class, Instrumentation.class);
                launch.setAccessible(true);

                RecordingInstrumentation persistRun = new RecordingInstrumentation(targetClass);
                launch.invoke(null, "persist=true", persistRun.proxy());
                assertNotNull(persistRun.addedTransformer, "persist=true should register a transformer");
                assertTrue(Files.exists(expectedBackup));

                RecordingInstrumentation restoreRun = new RecordingInstrumentation(targetClass);
                launch.invoke(null, "restore=true", restoreRun.proxy());
                assertSame(persistRun.addedTransformer, restoreRun.removedTransformer,
                        "restore=true should unregister the persisted transformer");
                assertNotNull(restoreRun.redefined, "restore=true should redefine the loaded class");
                assertArrayEquals(originalJarBytes, Files.readAllBytes(originalJar));
                assertFalse(Files.exists(expectedBackup), "restore=true should remove the backup");
            }
        } finally {
            Files.deleteIfExists(expectedBackup);
        }
    }

    @Test
    void persistArgumentIsOptIn() throws Exception {
        List<Class<?>> injectors = Arrays.asList(
                ApusicFilterChainAgentInjector.class,
                JettyHandlerAgentInjector.class,
                ResinFilterChainAgentInjector.class,
                UndertowServletHandlerAgentInjector.class,
                WebLogicServletContextAgentInjector.class,
                WebSphereFilterChainAgentInjector.class
        );
        for (Class<?> injector : injectors) {
            Method isPersistent = injector.getDeclaredMethod("isPersistent", String.class);
            isPersistent.setAccessible(true);
            assertFalse((Boolean) isPersistent.invoke(null, new Object[]{null}), injector.getName());
            assertFalse((Boolean) isPersistent.invoke(null, "persist=false"), injector.getName());
            assertTrue((Boolean) isPersistent.invoke(null, "other=value, persist=true"), injector.getName());
        }
    }

    @Test
    void transientAgentPackagesHookSupportWithoutPersistenceClasses() throws Exception {
        byte[] shellBytes = shellClass("test/SupportOnlyShell");
        InjectorConfig config = InjectorConfig.builder()
                .shellClassBytes(shellBytes)
                .shellClassName("test.SupportOnlyShell")
                .injectorClassName("test.SupportOnlyAgent")
                .injectorTemplateClassName(SpringWebMvcFrameworkServletAgentInjector.class.getName())
                .injectorTemplateClassLoader(SpringWebMvcFrameworkServletAgentInjector.class.getClassLoader())
                .build();
        InjectorGenerator generator = new InjectorGenerator(ShellConfig.builder()
                .shellType(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET).build(), config);

        Map<String, byte[]> classes = generator.getInnerClassBytes();

        assertTrue(classes.containsKey(AgentInjectorSupport.class.getName()));
        assertTrue(classes.containsKey(AgentInjectorSupport.Config.class.getName()));
        assertFalse(classes.keySet().stream()
                .anyMatch(name -> name.startsWith(AgentPersistence.class.getName())));
    }

    @Test
    void transientAgentRunsWithoutPersistenceCompanions() throws Exception {
        final String shellClassName = "test.TransientShell";
        final String injectorClassName = "test.TransientAgent";
        InjectorConfig config = InjectorConfig.builder()
                .shellClassBytes(shellClass(shellClassName.replace('.', '/')))
                .shellClassName(shellClassName)
                .injectorClassName(injectorClassName)
                .injectorTemplateClassName(SpringWebMvcFrameworkServletAgentInjector.class.getName())
                .injectorTemplateClassLoader(SpringWebMvcFrameworkServletAgentInjector.class.getClassLoader())
                .build();
        InjectorGenerator generator = new InjectorGenerator(ShellConfig.builder()
                .shellType(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET).build(), config);
        final Map<String, byte[]> classes = new HashMap<>();
        classes.put(injectorClassName, generator.generate());
        classes.putAll(generator.getInnerClassBytes());

        ClassLoader blockingParent = new ClassLoader(getClass().getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.startsWith(AgentPersistence.class.getName())) {
                    throw new ClassNotFoundException(name);
                }
                return super.loadClass(name, resolve);
            }
        };
        ClassLoader agentLoader = new ClassLoader(blockingParent) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] classBytes = classes.get(name);
                if (classBytes == null) {
                    throw new ClassNotFoundException(name);
                }
                return defineClass(name, classBytes, 0, classBytes.length);
            }
        };
        Class<?> injectorClass = Class.forName(injectorClassName, true, agentLoader);
        Method premain = injectorClass.getDeclaredMethod("premain", String.class, Instrumentation.class);
        RecordingInstrumentation instrumentation = new RecordingInstrumentation(null);
        premain.invoke(null, new Object[]{null, instrumentation.proxy()});

        assertNotNull(instrumentation.addedTransformer,
                "a transient agent must start without AgentPersistence on its classpath");
    }

    private static File invokePersist(Path agentJar, String injectorClassName, Class<?> targetClass) throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{agentJar.toUri().toURL()},
                AgentInjectorPersistenceTest.class.getClassLoader())) {
            Class<?> injectorClass = loader.loadClass(injectorClassName);
            Method persist = injectorClass.getDeclaredMethod("persist", Class.class);
            persist.setAccessible(true);
            return (File) persist.invoke(null, targetClass);
        }
    }

    private static void writeGeneratedAgent(Path agentJar, String injectorClassName, String shellClassName,
                                            byte[] shellClassBytes, String shellType,
                                            Class<?> injectorTemplateClass) throws IOException {
        InjectorConfig config = InjectorConfig.builder()
                .shellClassBytes(shellClassBytes)
                .shellClassName(shellClassName)
                .injectorClassName(injectorClassName)
                .injectorTemplateClassName(injectorTemplateClass.getName())
                .injectorTemplateClassLoader(injectorTemplateClass.getClassLoader())
                .build();
        InjectorGenerator generator = new InjectorGenerator(ShellConfig.builder().shellType(shellType).build(), config);
        Map<String, byte[]> classes = new HashMap<>();
        classes.put(injectorClassName, generator.generate());
        classes.putAll(generator.getInnerClassBytes());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(agentJar))) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                output.putNextEntry(new JarEntry(classEntry(entry.getKey())));
                output.write(entry.getValue());
                output.closeEntry();
            }
        }
    }

    private static String classEntry(String className) {
        return className.replace('.', '/') + ".class";
    }

    private static void writeJar(Path jarPath, String targetEntryName, byte[] targetClassBytes) throws IOException {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath))) {
            // 模拟由其他 JDK 或压缩级别生成的中间件 JAR，重写后压缩大小会改变。
            output.setLevel(Deflater.NO_COMPRESSION);
            output.putNextEntry(new JarEntry(targetEntryName));
            output.write(targetClassBytes);
            output.closeEntry();
            output.putNextEntry(new JarEntry("application.txt"));
            output.write("keep".getBytes("UTF-8"));
            output.closeEntry();
        }
    }

    private static byte[] readEntry(JarFile jarFile, String entryName) throws IOException {
        JarEntry entry = jarFile.getJarEntry(entryName);
        assertNotNull(entry, entryName);
        try (InputStream input = jarFile.getInputStream(entry)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
            }
            return output.toByteArray();
        }
    }

    private static byte[] targetClass(String internalName, String methodName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "invoked", "Z", null, null).visitEnd();
        defaultConstructor(writer);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_1);
        method.visitFieldInsn(Opcodes.PUTSTATIC, internalName, "invoked", "Z");
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] shellClass(String internalName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null);
        defaultConstructor(writer);
        MethodVisitor equals = writer.visitMethod(Opcodes.ACC_PUBLIC, "equals", "(Ljava/lang/Object;)Z", null, null);
        equals.visitCode();
        equals.visitInsn(Opcodes.ICONST_1);
        equals.visitInsn(Opcodes.IRETURN);
        equals.visitMaxs(0, 0);
        equals.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void defaultConstructor(ClassWriter writer) {
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
    }

    private static final class RecordingInstrumentation implements InvocationHandler {
        private final Class<?> targetClass;
        private ClassFileTransformer addedTransformer;
        private ClassFileTransformer removedTransformer;
        private ClassDefinition redefined;

        private RecordingInstrumentation(Class<?> targetClass) {
            this.targetClass = targetClass;
        }

        private Instrumentation proxy() {
            return (Instrumentation) Proxy.newProxyInstance(
                    AgentInjectorPersistenceTest.class.getClassLoader(),
                    new Class<?>[]{Instrumentation.class}, this);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            if ("getAllLoadedClasses".equals(name)) {
                return targetClass == null ? new Class<?>[0] : new Class<?>[]{targetClass};
            }
            if ("addTransformer".equals(name)) {
                addedTransformer = (ClassFileTransformer) args[0];
                return null;
            }
            if ("removeTransformer".equals(name)) {
                removedTransformer = (ClassFileTransformer) args[0];
                return true;
            }
            if ("redefineClasses".equals(name)) {
                redefined = ((ClassDefinition[]) args[0])[0];
                return null;
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == boolean.class) {
                return true;
            }
            if (returnType == int.class) {
                return 0;
            }
            if (returnType == long.class) {
                return 0L;
            }
            return null;
        }
    }
}
