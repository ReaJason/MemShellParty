package io.github.reajason.javaweb.proxy.alibaba;

import com.alibaba.dubbo.common.utils.NetUtils;
import com.alibaba.dubbo.config.ApplicationConfig;
import com.alibaba.dubbo.config.ReferenceConfig;
import com.alibaba.dubbo.config.RegistryConfig;
import com.alibaba.dubbo.rpc.service.GenericService;
import io.github.reajason.javaweb.proxy.ClientRuntimeSupport;
import io.github.reajason.javaweb.proxy.DubboHandler;
import io.github.reajason.javaweb.proxy.DubboProxyBridge;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicBoolean;

public class AlibabaDubboProxyClient {

    private static final String LOOPBACK_HOST = "127.0.0.1";

    public static void main(String[] args) throws Exception {
        ClientRuntimeSupport.prepareClientJvm();
        forceLoopbackLocalAddress();
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "usage: <listenHost> <listenPort> <dubboUrl> <interfaceName>");
        }

        final ReferenceConfig<GenericService> reference = new ReferenceConfig<GenericService>();
        reference.setApplication(new ApplicationConfig("alibaba-dubbo-proxy-client"));
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
            Runtime.getRuntime().addShutdownHook(new Thread(cleanup, "alibaba-dubbo-proxy-shutdown"));
            bridge.start();
            System.out.println("Dubbo proxy listening on " + args[0] + ":" + bridge.getLocalPort());
            bridge.await();
        } finally {
            cleanup.run();
        }
    }

    private static void forceLoopbackLocalAddress() {
        try {
            Field localAddressField = NetUtils.class.getDeclaredField("LOCAL_ADDRESS");
            localAddressField.setAccessible(true);
            localAddressField.set(null, InetAddress.getByName(LOOPBACK_HOST));
        } catch (Exception ignored) {
            // Best-effort workaround for Dubbo 2.6.x local address selection on macOS.
        }
    }
}
