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
        Class<?> aClass = defineClass(bytes, 0, bytes.length);
        Object o = null;
        try {
            o = aClass.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return o.toString();
    }
}
