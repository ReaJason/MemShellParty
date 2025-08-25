package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2025/8/25
 */
class ServerFactoryTest {

    @Test
    void testSupportedTools() {
        AbstractServer server = ServerFactory.getServer(Server.XXLJOB);
        Set<String> supportedShellTools = server.getSupportedShellTools();
        assertEquals(2, supportedShellTools.size());
        assertTrue(supportedShellTools.contains(ShellTool.Command));
        assertTrue(supportedShellTools.contains(ShellTool.Godzilla));
    }

}