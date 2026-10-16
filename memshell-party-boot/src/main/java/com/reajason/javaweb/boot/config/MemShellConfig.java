package com.reajason.javaweb.boot.config;

import com.reajason.javaweb.memshell.MemShellGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author ReaJason
 */
@Configuration
public class MemShellConfig {

    /**
     * 生成引擎本身无状态（底层共享 {@code MemShellRegistry} 单例），但「一个应用一份」这件事交给容器声明：
     * 控制器与服务各自 {@code new} 时行为等价，靠的是自觉，加个可变字段就会静默分裂。<p>
     * {@code MemShellGenerator} 在 core 模块（无 Spring 依赖，GUI / shelltool / 集成测试都在直接 new），
     * 所以只能在这里以 {@code @Bean} 暴露，不能给类加 {@code @Component}。
     */
    @Bean
    public MemShellGenerator memShellGenerator() {
        return new MemShellGenerator();
    }
}
