package com.reajason.javaweb.memshell.server.websphere;

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
@ServerMeta(name = Server.WebSphere, order = 70)
public class WebSphereServerProvider implements ServerProvider {

    @Override
    public AbstractServer createServer() {
        return new WebSphere();
    }
}
