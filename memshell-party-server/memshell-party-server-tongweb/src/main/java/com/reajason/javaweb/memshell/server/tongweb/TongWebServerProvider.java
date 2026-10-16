package com.reajason.javaweb.memshell.server.tongweb;

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
@ServerMeta(name = Server.TongWeb, order = 90)
public class TongWebServerProvider implements ServerProvider {

    @Override
    public AbstractServer createServer() {
        return new TongWeb();
    }
}
