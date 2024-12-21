package com.reajason.javaweb.buddy;

import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
class LogRemoveVisitorWrapperTest {

    @Test
    void testExtend() {
        DynamicType.Builder<?> builder = new ByteBuddy().subclass(Object.class);
        DynamicType.Builder<?> extendedBuilder = LogRemoveMethodVisitor.extend(builder);
        assertNotNull(extendedBuilder);
        assertNotEquals(builder, extendedBuilder);
    }

    @Test
    void testWrap() {
        LogRemoveMethodVisitor visitor = LogRemoveMethodVisitor.INSTANCE;
        TypeDescription instrumentedType = mock(TypeDescription.class);
        MethodDescription instrumentedMethod = mock(MethodDescription.class);
        MethodVisitor methodVisitor = mock(MethodVisitor.class);
        Implementation.Context implementationContext = mock(Implementation.Context.class);
        TypePool typePool = mock(TypePool.class);

        MethodVisitor wrappedVisitor = visitor.wrap(instrumentedType, instrumentedMethod, methodVisitor,
                implementationContext, typePool, 0, 0);

        assertNotNull(wrappedVisitor);
        assertNotEquals(methodVisitor, wrappedVisitor);
    }

    @Test
    void testVisitMethodInsn_RemoveSystemOutPrintln() {
        MethodVisitor methodVisitor = mock(MethodVisitor.class);
        LogRemoveMethodVisitor.INSTANCE.wrap(null, null, methodVisitor, null, null, 0, 0)
                .visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

        verify(methodVisitor, never()).visitMethodInsn(anyInt(), anyString(), anyString(), anyString(), anyBoolean());
    }

    @Test
    void testVisitMethodInsn_RemovePrintStackTrace() {
        MethodVisitor methodVisitor = mock(MethodVisitor.class);
        LogRemoveMethodVisitor.INSTANCE.wrap(null, null, methodVisitor, null, null, 0, 0)
                .visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V", false);

        verify(methodVisitor, never()).visitMethodInsn(anyInt(), anyString(), anyString(), anyString(), anyBoolean());
    }

    @Test
    void testVisitMethodInsn_KeepOtherMethodCalls() {
        MethodVisitor methodVisitor = mock(MethodVisitor.class);
        MethodVisitor wrappedVisitor = LogRemoveMethodVisitor.INSTANCE.wrap(null, null, methodVisitor, null, null, 0, 0);
        wrappedVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        verify(methodVisitor).visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
    }

    @Test
    void testIntegration() throws Exception {
        // Use ByteBuddy to create a new class with log statements removed
        DynamicType.Unloaded<TestClass> make = new ByteBuddy()
                .redefine(TestClass.class)
                .name("com.reajason.javaweb.buddy.TestClass1")
                .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(ElementMatchers.any(), LogRemoveMethodVisitor.INSTANCE))
                .make();
        byte[] bytes = make.getBytes();
//        Files.write(Paths.get("xx.class"), bytes);
        Class<?> modifiedClass = make.load(getClass().getClassLoader()).getLoaded();
        Object instance = modifiedClass.getDeclaredConstructor().newInstance();
        modifiedClass.getMethod("methodWithLogs").invoke(instance);
    }

    public static class TestClass {
        static Logger logger = Logger.getLogger(TestClass.class.getName());

        public TestClass() {
        }

        public static void methodWithLogs() {
            System.out.println("This should be removed");
            String test = "test";
            int length = test.length();
            logger.info(test);
            try {
                System.out.println("hello");
                throw new RuntimeException("hello");
            } catch (Exception e) {
                e.printStackTrace();
            }
            logger.warning("wa");
        }

        public static void main(String[] args) {
            methodWithLogs();
        }
    }
}