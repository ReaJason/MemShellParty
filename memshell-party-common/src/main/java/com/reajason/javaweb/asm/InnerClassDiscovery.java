package com.reajason.javaweb.asm;

import lombok.Getter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

public class InnerClassDiscovery {

    /**
     * Discovers all inner classes for a given class
     *
     * @param originalClass The class to discover inner classes for
     * @return A set of fully qualified inner class names
     */
    public static Set<String> findAllInnerClasses(Class<?> originalClass) throws IOException {
        Set<String> innerClasses;
        String resourceName = originalClass.getName().replace('.', '/') + ".class";
        try (InputStream is = originalClass.getClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) {
                throw new IOException("Could not find class file for " + originalClass.getName());
            }

            ClassReader reader = new ClassReader(is);
            InnerClassCollector collector = new InnerClassCollector(originalClass.getName());
            reader.accept(collector, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

            innerClasses = new HashSet<>(collector.getInnerClasses());
        }
        try {
            for (Class<?> innerClass : originalClass.getDeclaredClasses()) {
                innerClasses.add(innerClass.getName());
                innerClasses.addAll(findAllInnerClasses(innerClass));
            }
        } catch (SecurityException ignored) {
        }

        return innerClasses;
    }

    /**
     * Discovers all inner classes by reading class file resources only, so the classes
     * (and their supertypes) never need to be loadable on the consumer's classpath.
     *
     * @param className   binary name of the class to scan
     * @param classLoader loader that can see the class file resources
     * @return A set of fully qualified inner class names
     */
    public static Set<String> findAllInnerClasses(String className, ClassLoader classLoader) throws IOException {
        Set<String> innerClasses = new HashSet<>();
        collectInnerClasses(className, classLoader, innerClasses);
        return innerClasses;
    }

    private static void collectInnerClasses(String className, ClassLoader classLoader, Set<String> innerClasses) throws IOException {
        String resourceName = className.replace('.', '/') + ".class";
        try (InputStream is = classLoader.getResourceAsStream(resourceName)) {
            if (is == null) {
                throw new IOException("Could not find class file for " + className);
            }
            ClassReader reader = new ClassReader(is);
            InnerClassCollector collector = new InnerClassCollector(className);
            reader.accept(collector, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            for (String innerClass : collector.getInnerClasses()) {
                if (innerClasses.add(innerClass)) {
                    collectInnerClasses(innerClass, classLoader, innerClasses);
                }
            }
        }
    }

    private static class InnerClassCollector extends ClassVisitor {
        private final String originalClassName;
        @Getter
        private final Set<String> innerClasses = new HashSet<>();

        public InnerClassCollector(String originalClassName) {
            super(Opcodes.ASM9);
            this.originalClassName = originalClassName.replace('/', '.');
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            String className = name.replace('/', '.');
            if (outerName != null) {
                String outerClassName = outerName.replace('/', '.');
                if (outerClassName.equals(originalClassName)) {
                    innerClasses.add(className);
                }
            } else if (className.startsWith(originalClassName + "$")) {
                innerClasses.add(className);
            }
        }

    }
}