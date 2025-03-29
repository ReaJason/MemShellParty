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