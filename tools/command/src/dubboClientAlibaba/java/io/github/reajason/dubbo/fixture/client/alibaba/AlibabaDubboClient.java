package io.github.reajason.dubbo.fixture.client.alibaba;

import com.alibaba.dubbo.common.utils.NetUtils;
import com.alibaba.dubbo.config.ApplicationConfig;
import com.alibaba.dubbo.config.ReferenceConfig;
import com.alibaba.dubbo.config.RegistryConfig;
import com.alibaba.dubbo.rpc.service.GenericService;
import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;
import io.github.reajason.dubbo.fixture.client.ClientRuntimeSupport;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

public class AlibabaDubboClient {

    private static final String LOOPBACK_HOST = "127.0.0.1";

    public static void main(String[] args) {
        ClientRuntimeSupport.prepareClientJvm();
        forceLoopbackLocalAddress();
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: load-bytes <url> <base64> | run-command <url> <interfaceName> <command>");
        }
        if ("load-bytes".equals(args[0])) {
            if (args.length < 3) {
                throw new IllegalArgumentException("usage: load-bytes <url> <base64>");
            }
            System.out.println(loadBytes(args[1], args[2]));
            return;
        }
        if ("run-command".equals(args[0])) {
            if (args.length < 4) {
                throw new IllegalArgumentException("usage: run-command <url> <interfaceName> <command>");
            }
            Object result = runCommand(args[1], args[2], args[3]);
            if (result instanceof byte[]) {
                System.out.println(new String((byte[]) result, StandardCharsets.UTF_8));
            } else {
                System.out.println(String.valueOf(result));
            }
            return;
        }
        throw new IllegalArgumentException("unsupported action: " + args[0]);
    }

    public static String loadBytes(String url, String base64) {
        ClientRuntimeSupport.prepareClientJvm();
        forceLoopbackLocalAddress();
        ReferenceConfig<BytecodeLoadingService> reference = new ReferenceConfig<BytecodeLoadingService>();
        reference.setApplication(new ApplicationConfig("alibaba-dubbo-load-bytes-client"));
        reference.setRegistry(new RegistryConfig("N/A"));
        reference.setInterface(BytecodeLoadingService.class);
        reference.setCheck(false);
        reference.setTimeout(30000);
        reference.setRetries(0);
        reference.setUrl(url);

        BytecodeLoadingService loadingService = reference.get();
        try {
            return loadingService.loadBytes(base64);
        } finally {
            reference.destroy();
        }
    }

    public static Object runCommand(String url, String interfaceName, String command) {
        ClientRuntimeSupport.prepareClientJvm();
        forceLoopbackLocalAddress();
        ReferenceConfig<GenericService> reference = new ReferenceConfig<GenericService>();
        reference.setApplication(new ApplicationConfig("alibaba-dubbo-command-client"));
        reference.setRegistry(new RegistryConfig("N/A"));
        reference.setInterface(interfaceName);
        reference.setGeneric(true);
        reference.setCheck(false);
        reference.setTimeout(30000);
        reference.setRetries(0);
        reference.setUrl(url);

        GenericService genericService = reference.get();
        try {
            return genericService.$invoke(
                    "handle",
                    new String[]{byte[].class.getName()},
                    new Object[]{command.getBytes(StandardCharsets.UTF_8)}
            );
        } finally {
            reference.destroy();
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
