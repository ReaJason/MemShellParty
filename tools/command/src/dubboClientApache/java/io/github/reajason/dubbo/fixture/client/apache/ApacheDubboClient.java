package io.github.reajason.dubbo.fixture.client.apache;

import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;
import io.github.reajason.dubbo.fixture.client.ClientRuntimeSupport;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.rpc.service.GenericService;

import java.nio.charset.StandardCharsets;

public class ApacheDubboClient {

    public static void main(String[] args) {
        ClientRuntimeSupport.prepareClientJvm();
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
        ReferenceConfig<BytecodeLoadingService> reference = new ReferenceConfig<BytecodeLoadingService>();
        reference.setApplication(new ApplicationConfig("apache-dubbo-load-bytes-client"));
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
        ReferenceConfig<GenericService> reference = new ReferenceConfig<GenericService>();
        reference.setApplication(new ApplicationConfig("apache-dubbo-command-client"));
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
}
