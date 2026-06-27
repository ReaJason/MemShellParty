package io.github.reajason.dubbo.fixture.alibaba;

import com.alibaba.dubbo.config.ApplicationConfig;
import com.alibaba.dubbo.config.ProtocolConfig;
import com.alibaba.dubbo.config.RegistryConfig;
import com.alibaba.dubbo.config.ServiceConfig;
import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;
import io.github.reajason.dubbo.fixture.api.DemoService;
import io.github.reajason.dubbo.fixture.common.BytecodeLoadingServiceImpl;
import io.github.reajason.dubbo.fixture.common.DemoServiceImpl;
import io.github.reajason.dubbo.fixture.common.LoadBytesExportContext;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

public class AlibabaDubbo2Provider {

    public static void main(String[] args) throws InterruptedException {
        System.setProperty("dubbo.compiler", "jdk");
        ApplicationConfig application = new ApplicationConfig("alibaba-dubbo2-provider");
        application.setQosEnable(true);
        application.setQosPort(22221);

        ProtocolConfig dubboProtocol = new ProtocolConfig();
        dubboProtocol.setName("dubbo");
        dubboProtocol.setPort(20880);

        ProtocolConfig hessianProtocol = new ProtocolConfig();
        hessianProtocol.setName("hessian");
        hessianProtocol.setPort(28080);

        ProtocolConfig httpProtocol = new ProtocolConfig();
        httpProtocol.setName("http");
        httpProtocol.setPort(28081);

        RegistryConfig registry = new RegistryConfig("N/A");
        LoadBytesExportContext.register(application, registry, Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));

        ServiceConfig<DemoService> demoService = new ServiceConfig<DemoService>();
        demoService.setApplication(application);
        demoService.setRegistry(registry);
        demoService.setProtocols(Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));
        demoService.setInterface(DemoService.class);
        demoService.setRef(new DemoServiceImpl("alibaba-dubbo-2.6.12"));
        demoService.export();

        ServiceConfig<BytecodeLoadingService> loaderService = new ServiceConfig<BytecodeLoadingService>();
        loaderService.setApplication(application);
        loaderService.setRegistry(registry);
        loaderService.setProtocols(Arrays.asList(dubboProtocol, hessianProtocol, httpProtocol));
        loaderService.setInterface(BytecodeLoadingService.class);
        loaderService.setRef(new BytecodeLoadingServiceImpl());
        loaderService.export();

        System.out.println("==============================================");
        System.out.println(" alibaba-dubbo 2.6.12 Provider started");
        System.out.println(" dubbo   -> dubbo://127.0.0.1:20880");
        System.out.println(" hessian -> hessian://127.0.0.1:28080");
        System.out.println(" http    -> http://127.0.0.1:28081");
        System.out.println(" qos     -> 127.0.0.1:22221");
        System.out.println("==============================================");

        new CountDownLatch(1).await();
    }
}
