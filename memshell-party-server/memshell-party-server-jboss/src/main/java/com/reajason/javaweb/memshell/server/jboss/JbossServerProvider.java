package com.reajason.javaweb.memshell.server.jboss;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.spi.ServerMeta;
import com.reajason.javaweb.memshell.spi.ServerProvider;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 3.0.0
 */
@MetaInfServices(ServerProvider.class)
@ServerMeta(name = Server.JBoss, order = 40)
public class JbossServerProvider implements ServerProvider {

    @Override
    public AbstractServer createServer() {
        return new Jboss();
    }
}
