package com.reajason.javaweb.memshell.server.apusic;

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
@ServerMeta(name = Server.Apusic, order = 120)
public class ApusicServerProvider implements ServerProvider {

    @Override
    public AbstractServer createServer() {
        return new Apusic();
    }
}
