package com.reajason.javaweb.asm;

import org.objectweb.asm.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
public class ClassAnnotationUtils {

    public static byte[] setAnnotation(byte[] bytes, String annotationClassName) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(cr, 0);
        ClassVisitor cv = new AddAnnotationClassVisitor(cw, annotationClassName);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    static class AddAnnotationClassVisitor extends ClassVisitor {
        private final String annotationClassName;

        public AddAnnotationClassVisitor(ClassVisitor cv, String annotationClassName) {
            super(Opcodes.ASM9, cv);
            this.annotationClassName = annotationClassName.replace('.', '/');
        }

        @Override
        public void visit(
                int version, int access, String name,
                String signature, String superName, String[] interfaces) {

            super.visit(version, access, name, signature, superName, interfaces);
            super.visitAnnotation(
                    "L" + annotationClassName + ";",
                    true
            ).visitEnd();
        }
    }

    public static List<AnnotationInfo> getAnnotations(byte[] classBytes) {
        ClassReader cr = new ClassReader(classBytes);
        AnnotationCollectingVisitor cv = new AnnotationCollectingVisitor();
        cr.accept(cv, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return cv.getAnnotations();
    }

    public static class AnnotationInfo {
        public final String desc;
        public final Map<String, Object> values = new HashMap<>();

        public AnnotationInfo(String desc) {
            this.desc = desc;
        }
    }

    public static class AnnotationCollectingVisitor extends ClassVisitor {

        private final List<AnnotationInfo> annotations = new ArrayList<>();

        public AnnotationCollectingVisitor() {
            super(Opcodes.ASM9);
        }

        public List<AnnotationInfo> getAnnotations() {
            return annotations;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            AnnotationInfo info = new AnnotationInfo(descriptor);
            annotations.add(info);

            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override
                public void visit(String name, Object value) {
                    info.values.put(name, value);
                }

                @Override
                public AnnotationVisitor visitArray(String name) {
                    List<Object> array = new ArrayList<>();
                    info.values.put(name, array);

                    return new AnnotationVisitor(Opcodes.ASM9) {
                        @Override
                        public void visit(String name, Object value) {
                            array.add(value);
                        }
                    };
                }
            };
        }
    }
}
