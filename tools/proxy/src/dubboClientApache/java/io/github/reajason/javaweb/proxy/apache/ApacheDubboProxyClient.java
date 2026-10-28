package io.github.reajason.javaweb.proxy.apache;

import io.github.reajason.javaweb.proxy.ClientRuntimeSupport;
import io.github.reajason.javaweb.proxy.DubboHandler;
import io.github.reajason.javaweb.proxy.DubboProxyBridge;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.rpc.service.GenericService;

import java.util.concurrent.atomic.AtomicBoolean;

public class ApacheDubboProxyClient {

    public static void main(String[] args) throws Exception {
        ClientRuntimeSupport.prepareClientJvm();
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "usage: <listenHost> <listenPort> <dubboUrl> <interfaceName>");
        }

        final ReferenceConfig<GenericService> reference = new ReferenceConfig<GenericService>();
        reference.setApplication(new ApplicationConfig("apache-dubbo-proxy-client"));
        reference.setRegistry(new RegistryConfig("N/A"));
        reference.setInterface(args[3]);
        reference.setGeneric(true);
        reference.setCheck(false);
        reference.setRetries(0);
        reference.setTimeout(30000);
        reference.setUrl(args[2]);

        final GenericService genericService;
        try {
            genericService = reference.get();
        } catch (RuntimeException e) {
            reference.destroy();
            throw e;
        }
        final DubboProxyBridge bridge = new DubboProxyBridge(
                args[0], Integer.parseInt(args[1]), new DubboHandler() {
            @Override
            public byte[] handle(byte[] request) {
                return (byte[]) genericService.$invoke(
                        "handle",
                        new String[]{byte[].class.getName()},
                        new Object[]{request});
            }
        });
        final AtomicBoolean cleanedUp = new AtomicBoolean();
        final Runnable cleanup = new Runnable() {
            @Override
            public void run() {
                if (cleanedUp.compareAndSet(false, true)) {
                    bridge.close();
                    reference.destroy();
                }
            }
        };
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(cleanup, "apache-dubbo-proxy-shutdown"));
            bridge.start();
            System.out.println("Dubbo proxy listening on " + args[0] + ":" + bridge.getLocalPort());
            bridge.await();
        } finally {
            cleanup.run();
        }
    }
}
