package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.asm.ClassReferenceVisitor;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandListener;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;


/**
 * @author ReaJason
 * @since 2025/3/19
 */
class CustomShellGeneratorTest {
    @Test
    @SneakyThrows
    void testListener() {
        byte[] bytes = new ByteBuddy()
                .redefine(CommandListener.class)
                .name(CommonUtil.generateShellClassName()).make().getBytes();
        String className = CommonUtil.generateShellClassName();
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.LISTENER)
                .build();
        CustomConfig customConfig = CustomConfig.builder()
                .shellClassName(className)
                .shellClassBase64(Base64.getEncoder().encodeToString(bytes))
                .shellTypeDescription(TypeDescription.ForLoadedType.of(CommandListener.class))
                .build();
        byte[] bytes1 = new CustomShellGenerator(shellConfig, customConfig).getBytes();

        ClassReader classReader = new ClassReader(bytes1);
        assertEquals(className, classReader.getClassName().replace("/", "."));
    }

    @Test
    @SneakyThrows
    void testFilter() {
        byte[] bytes = new ByteBuddy()
                .subclass(Object.class)
                .name(CommonUtil.generateShellClassName()).make().getBytes();
        String className = CommonUtil.generateShellClassName();
        ShellConfig shellConfig = ShellConfig.builder()
                .shellType(ShellType.FILTER)
                .build();
        CustomConfig customConfig = CustomConfig.builder()
                .shellClassName(className)
                .shellClassBase64(Base64.getEncoder().encodeToString(bytes))
                .build();
        byte[] bytes1 = new CustomShellGenerator(shellConfig, customConfig).getBytes();

        ClassReader classReader = new ClassReader(bytes1);
        assertEquals(className, classReader.getClassName().replace("/", "."));
    }

    @Test
    @SneakyThrows
    void testValue() {
        byte[] bytes = new ByteBuddy()
                .redefine(GodzillaValve.class)
                .name(CommonUtil.generateShellClassName()).make().getBytes();
        String className = CommonUtil.generateShellClassName();
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.BES)
                .shellType(ShellType.VALVE)
                .build();
        CustomConfig customConfig = CustomConfig.builder()
                .shellClassName(className)
                .shellClassBase64(Base64.getEncoder().encodeToString(bytes))
                .build();
        byte[] bytes1 = new CustomShellGenerator(shellConfig, customConfig).getBytes();

        ClassReader classReader = new ClassReader(bytes1);
        ClassReferenceVisitor classVisitor = new ClassReferenceVisitor();
        classReader.accept(classVisitor, 0);
        Set<String> referencedClasses = classVisitor.getReferencedClasses();
        assertEquals(className, classReader.getClassName().replace("/", "."));
        assertTrue(referencedClasses.contains("com/bes/enterprise/webtier/Valve"));
        assertFalse(referencedClasses.contains("org/apache/catalina/Valve"));
    }
}