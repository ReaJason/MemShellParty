package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ObfuscationScope;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class MemShellObfuscationScopeTest {

    @Test
    void scopeDefaultsToAllIncludingDeserializedNull() {
        assertEquals(ObfuscationScope.ALL, ShellConfig.builder().build().getObfuscationScope());
        ShellConfig config = new ShellConfig();
        config.setObfuscationScope(null);
        assertEquals(ObfuscationScope.ALL, config.getObfuscationScope());
    }

    @Test
    void memshellScopeLeavesMainInjectorUnobfuscated() {
        MemShellResult result = generate(Server.Tomcat, ShellType.FILTER,
                ObfuscationScope.MEMSHELL, false);

        assertTrue(methodNames(result.getInjectorBytes()).contains("getErrorMessage"));
        assertEquals(0, result.getObfuscationInfo().getOriginalInjectorSize());
    }

    @Test
    void injectorScopeObfuscatesMainInjector() {
        MemShellResult result = generate(Server.Tomcat, ShellType.FILTER,
                ObfuscationScope.MEMSHELL_INJECTOR, false);

        assertFalse(methodNames(result.getInjectorBytes()).contains("getErrorMessage"));
        assertTrue(result.getObfuscationInfo().getOriginalInjectorSize() > 0);
    }

    @Test
    void injectorOnlyScopeObfuscatesInjectorButNotShell() {
        MemShellResult result = generate(Server.Tomcat, ShellType.FILTER,
                ObfuscationScope.INJECTOR, false);

        assertEquals(0, result.getObfuscationInfo().getOriginalShellSize());
        assertEquals(0, result.getObfuscationInfo().getObfuscatedShellSize());
        assertFalse(methodNames(result.getInjectorBytes()).contains("getErrorMessage"));
        assertTrue(result.getObfuscationInfo().getOriginalInjectorSize() > 0);
    }

    @Test
    void injectorScopeIncludesPersistenceCompanions() {
        MemShellResult shellOnly = generate(Server.Tomcat, ShellType.AGENT_FILTER_CHAIN,
                ObfuscationScope.MEMSHELL, false);
        byte[] plainPersistence = shellOnly.getInjectorInnerClassBytes().get(AgentPersistence.class.getName());
        assertNotNull(plainPersistence);
        assertTrue(methodNames(plainPersistence).contains("resolveDeploymentJar"));

        for (ObfuscationScope scope : new ObfuscationScope[]{
                ObfuscationScope.MEMSHELL_INJECTOR, ObfuscationScope.INJECTOR}) {
            MemShellResult injectorScope = generate(Server.Tomcat, ShellType.AGENT_FILTER_CHAIN, scope, false);
            Map<String, byte[]> companions = injectorScope.getInjectorInnerClassBytes();
            byte[] persistence = companions.get(AgentPersistence.class.getName());
            assertNotNull(persistence, scope.name());
            Set<String> persistenceMethods = methodNames(persistence);
            assertFalse(persistenceMethods.contains("resolveDeploymentJar"), scope.name());
            assertTrue(persistenceMethods.contains("persist"), scope.name());
            assertTrue(persistenceMethods.contains("isPersistent"), scope.name());
            byte[] transformer = companions.get(AgentPersistence.Transformer.class.getName());
            assertNotNull(transformer, scope.name());
            assertTrue(methodNames(transformer).contains("transform"), scope.name());
        }
    }

    @Test
    void allScopeKeepsDubboServiceInterfaceLoadable() throws Exception {
        MemShellResult result = generate(Server.Dubbo, ShellType.APACHE_DUBBO_SERVICE,
                ObfuscationScope.ALL, false);

        GeneratedClassLoader loader = new GeneratedClassLoader();
        Class<?> serviceInterface = loader.define(result.getHelperClassName(), result.getHelperBytes());
        Class<?> service = loader.define(result.getShellClassName(), result.getShellBytes());
        assertTrue(serviceInterface.isInterface());
        assertTrue(serviceInterface.isAssignableFrom(service));
        assertNotNull(serviceInterface.getMethod("handle", byte[].class));
    }

    @Test
    void injectorScopeKeepsPersistenceCompanionsLoadable() throws Exception {
        MemShellResult result = generate(Server.Tomcat, ShellType.AGENT_FILTER_CHAIN,
                ObfuscationScope.ALL, false);

        GeneratedClassLoader loader = new GeneratedClassLoader();
        for (Map.Entry<String, byte[]> entry : result.getInjectorInnerClassBytes().entrySet()) {
            loader.define(entry.getKey(), entry.getValue());
        }
        loader.define(result.getInjectorClassName(), result.getInjectorBytes());
        Class<?> persistence = loader.loadClass(AgentPersistence.class.getName());
        assertEquals(true, persistence.getMethod("isPersistent", String.class)
                .invoke(null, "persist=true"));
    }

    @Test
    void allScopeAddsHelperAndResponseWrapper() {
        for (ObfuscationScope scope : new ObfuscationScope[]{
                ObfuscationScope.MEMSHELL_INJECTOR, ObfuscationScope.INJECTOR}) {
            MemShellResult injectorScope = generate(Server.Tomcat, ShellType.RAW_WEBSOCKET, scope, true);
            assertTrue(methodNames(injectorScope.getHelperBytes()).contains("connect"), scope.name());
            assertTrue(methodNames(injectorScope.getInjectorBytes()).contains("getDataFromReq"), scope.name());
        }

        MemShellResult all = generate(Server.Tomcat, ShellType.RAW_WEBSOCKET,
                ObfuscationScope.ALL, true);
        Set<String> helperMethods = methodNames(all.getHelperBytes());
        assertFalse(helperMethods.contains("connect"));
        assertTrue(helperMethods.contains("equals"));
        assertTrue(helperMethods.contains("run"));
        assertTrue(helperMethods.contains("close"));
        assertFalse(methodNames(all.getInjectorBytes()).contains("getDataFromReq"));
    }

    private static MemShellResult generate(String server, String shellType,
                                           ObfuscationScope scope, boolean probe) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(ShellTool.Command)
                .shellType(shellType)
                .targetJreVersion(Opcodes.V1_8)
                .obfuscation(ObfuscationConfig.enabled())
                .obfuscationScope(scope)
                .probe(probe ? ProbeConfig.builder().build() : null)
                .build();
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .injectorClassName("test.ScopeInjector")
                .urlPattern(ShellType.RAW_WEBSOCKET.equals(shellType) ? "/raw-ws" : "/*")
                .build();
        Map<String, String> params = new HashMap<>();
        params.put("shellClassName", "test.ScopeShell");
        params.put("paramName", "cmd");
        return new MemShellGenerator().generate(shellConfig, injectorConfig, params);
    }

    private static final class GeneratedClassLoader extends ClassLoader {
        private GeneratedClassLoader() {
            super(MemShellObfuscationScopeTest.class.getClassLoader());
        }

        private Class<?> define(String className, byte[] classBytes) {
            Class<?> loaded = findLoadedClass(className);
            return loaded != null ? loaded : defineClass(className, classBytes, 0, classBytes.length);
        }
    }

    private static Set<String> methodNames(byte[] classBytes) {
        Set<String> names = new LinkedHashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return Collections.unmodifiableSet(names);
    }
}
