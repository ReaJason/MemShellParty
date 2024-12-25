package com.reajason.javaweb.vul.springboot2.controller;

import com.reajason.javaweb.vul.springboot2.ClassDefiner;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
@RequestMapping("/b64")
public class Base64ClassLoaderController {
    @PostMapping
    public Mono<String> handleFormSubmission(ServerWebExchange exchange) {
        System.out.println("hello i'm coming");
        return exchange.getFormData()
                .flatMap(formData -> {
                    String data = formData.getFirst("data");
                    System.out.println("b64: " + data);
                    byte[] bytes = Base64.getDecoder().decode(data);
                    Object o = null;
                    try {
                        o = new ClassDefiner(Thread.currentThread().getContextClassLoader()).defineClass(bytes).newInstance();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return Mono.just(o.toString());
                });
    }
}
