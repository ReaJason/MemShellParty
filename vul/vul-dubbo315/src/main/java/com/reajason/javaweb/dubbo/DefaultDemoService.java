package com.reajason.javaweb.dubbo;

import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.beans.factory.annotation.Value;

@DubboService(version = "1.0.0", path = "demo_say_hello")
public class DefaultDemoService extends ClassLoader implements DemoService {
    /**
     * The default value of ${dubbo.application.name} is ${spring.application.name}
     */
    @Value("${dubbo.application.name}")
    private String serviceName;

    public DefaultDemoService() {
        super(Thread.currentThread().getContextClassLoader());
    }

    public String sayHello(String name) {
        return String.format("[%s] : Hello, %s", serviceName, name);
    }

    @Override
    public String loadBytes(byte[] bytes) {
        System.out.println("i am in");
        Class<?> aClass = defineClass(bytes, 0, bytes.length);
        System.out.println("define class");
        Object o = null;
        try {
            System.out.println("new instance");
            o = aClass.newInstance();
        } catch (Exception e) {
            System.out.println("error for new instance");
            e.printStackTrace();
        }
        return String.format("[%s] : Hello, %s", serviceName, o.toString());
    }
}
