package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.Remapper;
import net.bytebuddy.pool.TypePool;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

/**
 * 修改方法中局部变量的赋值
 *
 * @author ReaJason
 * @since 2025/1/5
 */
public class LdcReAssignVisitorWrapper implements AsmVisitorWrapper {
    private final Map<Object, Object> map;

    public LdcReAssignVisitorWrapper(Map<Object, Object> map) {
        this.map = map;
    }

    @Override
    public int mergeWriter(int flags) {
        return flags;
    }

    @Override
    public int mergeReader(int flags) {
        return flags;
    }

    @Override
    public @NotNull ClassVisitor wrap(@NotNull TypeDescription instrumentedType, @NotNull ClassVisitor classVisitor,
                                      Implementation.@NotNull Context implementationContext, @NotNull TypePool typePool,
                                      @NotNull FieldList<FieldDescription.InDefinedShape> fields,
                                      @NotNull MethodList<?> methods, int writerFlags, int readerFlags) {
        return new ClassRemapper(classVisitor, new Remapper() {
            @Override
            public Object mapValue(Object value) {
                if (map.containsKey(value)) {
                    return map.get(value);
                }
                return value;
            }
        });
    }
}
