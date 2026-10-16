package com.reajason.javaweb.memshell.server.jetty5;

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
@ServerMeta(name = Server.Jetty5, order = 25)
public class Jetty5ServerProvider implements ServerProvider {

    @Override
    public AbstractServer createServer() {
        return new Jetty5();
    }
}
