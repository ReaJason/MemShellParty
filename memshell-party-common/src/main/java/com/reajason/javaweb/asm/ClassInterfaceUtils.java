package com.reajason.javaweb.asm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2025/11/16
 */
public class ClassInterfaceUtils {

    public static byte[] addInterface(byte[] bytes, String interfaceName) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(cr, 0);
        ClassVisitor cv = new AddInterfaceClassAdapter(cw, interfaceName.replace('.', '/'));
        cr.accept(cv, 0);
        return cw.toByteArray();
    }


    static class AddInterfaceClassAdapter extends ClassVisitor {

        private final String interfaceToAdd;

        public AddInterfaceClassAdapter(ClassVisitor cv, String interfaceToAdd) {
            super(Opcodes.ASM9, cv);
            this.interfaceToAdd = interfaceToAdd;
        }

        @Override
        public void visit(int version, int access, String name,
                          String signature, String superName, String[] interfaces) {
            for (String itf : interfaces) {
                if (itf.equals(interfaceToAdd)) {
                    super.visit(version, access, name, signature, superName, interfaces);
                    return;
                }
            }
            String[] newInterfaces = new String[interfaces.length + 1];
            System.arraycopy(interfaces, 0, newInterfaces, 0, interfaces.length);
            newInterfaces[interfaces.length] = interfaceToAdd;
            super.visit(version, access, name, signature, superName, newInterfaces);
        }
    }
}
