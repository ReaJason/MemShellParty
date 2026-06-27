package io.github.reajason.dubbo.fixture.apache2;

import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;
import io.github.reajason.dubbo.fixture.api.DemoService;
import io.github.reajason.dubbo.fixture.common.BytecodeLoadingServiceImpl;
import io.github.reajason.dubbo.fixture.common.DemoServiceImpl;
import io.github.reajason.dubbo.fixture.common.LoadBytesExportContext;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

public final class ApacheDubbo2Provider {

    private ApacheDubbo2Provider() {
    }

    public static void start(String providerName, int dubboPort, int hessianPort, int httpPort, int qosPort)
            throws InterruptedException {
        System.setProperty("dubbo.compiler", "jdk");
        ApplicationConfig application = new ApplicationConfig(providerName + "-provider");
        application.setQosEnable(true);
        application.setQosPort(qosPort);

        ProtocolConfig dubboProtocol = new ProtocolConfig();
        dubboProtocol.setName("dubbo");
        dubboProtocol.setPort(dubboPort);

        ProtocolConfig hessianProtocol = new ProtocolConfig();
        hessianProtocol.setName("hessian");
        hessianProtocol.setPort(hessianPort);
        hessianProtocol.setServer("tomcat");

        ProtocolConfig httpProtocol = new ProtocolConfig();
        httpProtocol.setName("http");
        httpProtocol.setPort(httpPort);
        httpProtocol.setServer("tomcat");

        RegistryConfig registry = new RegistryConfig("N/A");
        LoadBytesExportContext.register(application, registry, Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));

        ServiceConfig<DemoService> demoService = new ServiceConfig<DemoService>();
        demoService.setApplication(application);
        demoService.setRegistry(registry);
        demoService.setProtocols(Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));
        demoService.setInterface(DemoService.class);
        demoService.setRef(new DemoServiceImpl(providerName));
        demoService.export();

        ServiceConfig<BytecodeLoadingService> loaderService = new ServiceConfig<BytecodeLoadingService>();
        loaderService.setApplication(application);
        loaderService.setRegistry(registry);
        loaderService.setProtocols(Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));
        loaderService.setInterface(BytecodeLoadingService.class);
        loaderService.setRef(new BytecodeLoadingServiceImpl());
        loaderService.export();

        System.out.println("==============================================");
        System.out.println(" " + providerName + " Provider started");
        System.out.println(" dubbo   -> dubbo://127.0.0.1:" + dubboPort);
        System.out.println(" hessian -> hessian://127.0.0.1:" + hessianPort);
        System.out.println(" http    -> http://127.0.0.1:" + httpPort);
        System.out.println(" qos     -> 127.0.0.1:" + qosPort);
        System.out.println("==============================================");

        new CountDownLatch(1).await();
    }
}
