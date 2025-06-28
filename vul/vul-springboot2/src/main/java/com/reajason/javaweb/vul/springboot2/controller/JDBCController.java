package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
@RestController
public class JDBCController {

    @PostMapping("/jdbc")
    public void JDBC(String data) throws Exception {
        try {
            Connection connection = DriverManager.getConnection(data);
            connection.close();
        } catch (Throwable e) {
            Throwable ex = e.getCause();
            while (ex.getCause() != null) {
                ex = ex.getCause();
            }
            if (!(ex instanceof ClassCastException)) {
                throw e;
            }
        }
    }
}
