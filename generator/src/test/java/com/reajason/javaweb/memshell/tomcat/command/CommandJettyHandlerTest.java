package com.reajason.javaweb.memshell.tomcat.command;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;
import com.reajason.javaweb.memshell.shelltool.command.CommandJettyHandler;
import net.bytebuddy.jar.asm.ClassReader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author ReaJason
 * @since 2025/12/2
 */
public class CommandJettyHandlerTest {
    @Test
    void testJetty6() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .serverVersion("6")
                .shellTool(ShellTool.Command)
                .shellType(ShellType.HANDLER)
                .debug(true)
                .build();
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(CommandJettyHandler.class)
                .shellClassName(CommandJettyHandler.class.getName())
                .paramName("pwd").build();
        CommandGenerator commandGenerator = new CommandGenerator(shellConfig, commandConfig);
        byte[] bytes = commandGenerator.getBytes();
        assertEquals("org/mortbay/jetty/handler/AbstractHandler", new ClassReader(bytes).getSuperName());
    }

    @Test
    void testJetty7Plus() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .serverVersion("7+")
                .shellTool(ShellTool.Command)
                .shellType(ShellType.HANDLER)
                .debug(true)
                .build();
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(CommandJettyHandler.class)
                .shellClassName(CommandJettyHandler.class.getName())
                .paramName("pwd").build();
        CommandGenerator commandGenerator = new CommandGenerator(shellConfig, commandConfig);
        byte[] bytes = commandGenerator.getBytes();
        assertEquals("org/eclipse/jetty/server/handler/AbstractHandler", new ClassReader(bytes).getSuperName());
    }

    @Test
    void testJetty12() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .serverVersion("12")
                .shellTool(ShellTool.Command)
                .shellType(ShellType.HANDLER)
                .debug(true)
                .build();
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(CommandJettyHandler.class)
                .shellClassName(CommandJettyHandler.class.getName())
                .paramName("pwd").build();
        CommandGenerator commandGenerator = new CommandGenerator(shellConfig, commandConfig);
        byte[] bytes = commandGenerator.getBytes();
        assertEquals("org/eclipse/jetty/server/Handler$Abstract", new ClassReader(bytes).getSuperName());
    }

    @Test
    void testJettyException() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .serverVersion("unknown")
                .shellTool(ShellTool.Command)
                .shellType(ShellType.HANDLER)
                .debug(true)
                .build();
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(CommandJettyHandler.class)
                .shellClassName(CommandJettyHandler.class.getName())
                .paramName("pwd").build();
        CommandGenerator commandGenerator = new CommandGenerator(shellConfig, commandConfig);
        assertThrows(GenerationException.class, commandGenerator::getBytes);
    }

    @Test
    void testJettyNullException() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Jetty)
                .serverVersion(null)
                .shellTool(ShellTool.Command)
                .shellType(ShellType.HANDLER)
                .debug(true)
                .build();
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(CommandJettyHandler.class)
                .shellClassName(CommandJettyHandler.class.getName())
                .paramName("pwd").build();
        CommandGenerator commandGenerator = new CommandGenerator(shellConfig, commandConfig);
        assertThrows(GenerationException.class, commandGenerator::getBytes);
    }
}
