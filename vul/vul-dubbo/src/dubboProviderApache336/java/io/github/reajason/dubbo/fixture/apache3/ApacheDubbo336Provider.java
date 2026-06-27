package io.github.reajason.dubbo.fixture.apache3;

import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;
import io.github.reajason.dubbo.fixture.api.DemoService;
import io.github.reajason.dubbo.fixture.common.BytecodeLoadingServiceImpl;
import io.github.reajason.dubbo.fixture.common.DemoServiceImpl;
import io.github.reajason.dubbo.fixture.common.LoadBytesExportContext;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;
import org.apache.dubbo.config.bootstrap.DubboBootstrap;

import java.util.Arrays;

public class ApacheDubbo336Provider {

    public static void main(String[] args) {
        System.setProperty("dubbo.compiler", "jdk");
        ApplicationConfig application = new ApplicationConfig("apache-dubbo-3.3.6-provider");
        application.setQosEnable(true);
        application.setQosPort(22223);

        RegistryConfig registry = new RegistryConfig("N/A");
        ProtocolConfig dubboProtocol = new ProtocolConfig("dubbo", 20882);
        ProtocolConfig triProtocol = new ProtocolConfig("tri", 50051);
        ProtocolConfig hessianProtocol = new ProtocolConfig("hessian", 28084);
        ProtocolConfig httpProtocol = new ProtocolConfig("http", 28085);
        LoadBytesExportContext.register(
                application,
                registry,
                Arrays.asList(dubboProtocol, triProtocol, hessianProtocol, httpProtocol)
        );

        ServiceConfig<DemoService> demoService = new ServiceConfig<DemoService>();
        demoService.setInterface(DemoService.class);
        demoService.setRef(new DemoServiceImpl("apache-dubbo-3.3.6"));

        ServiceConfig<BytecodeLoadingService> loaderService = new ServiceConfig<BytecodeLoadingService>();
        loaderService.setInterface(BytecodeLoadingService.class);
        loaderService.setRef(new BytecodeLoadingServiceImpl());

        DubboBootstrap.getInstance()
                .application(application)
                .registry(registry)
                .protocol(dubboProtocol)
                .protocol(triProtocol)
                .protocol(hessianProtocol)
                .protocol(httpProtocol)
                .service(demoService)
                .service(loaderService)
                .start();

        System.out.println("==============================================");
        System.out.println(" apache-dubbo-3.3.6 Provider started");
        System.out.println(" dubbo   -> dubbo://127.0.0.1:20882");
        System.out.println(" tri     -> tri://127.0.0.1:50051");
        System.out.println(" hessian -> hessian://127.0.0.1:28084");
        System.out.println(" http    -> http://127.0.0.1:28085");
        System.out.println(" qos     -> 127.0.0.1:22223");
        System.out.println("==============================================");

        DubboBootstrap.getInstance().await();
    }
}
