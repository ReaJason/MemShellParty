package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
public class IndexController {

    /**
     * 监听器内存马在 requestInitialized 里直接写 response，这里再返回响应体会让
     * Spring MVC 的 MessageConverter 触发 getWriter/getOutputStream 冲突。
     * 与 war 靶场的 TestServlet 一致，保留不写响应。
     */
    @RequestMapping("/test")
    public void test() {
    }

    @GetMapping("/")
    public String index() {
        return "hello";
    }
}
