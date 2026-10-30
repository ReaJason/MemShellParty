package com.reajason.javaweb.examples.plugin;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.spi.ServerMeta;
import com.reajason.javaweb.memshell.spi.ServerProvider;
import org.kohsuke.MetaInfServices;

@MetaInfServices(ServerProvider.class)
@ServerMeta(name = ExampleServerProvider.NAME, order = 1000)
public class ExampleServerProvider implements ServerProvider {
    public static final String NAME = "ExamplePluginServer";

    @Override
    public AbstractServer createServer() {
        return new ExampleServer();
    }
}
