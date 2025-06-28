package com.reajason.javaweb.vul.springboot2.controller;

import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
public class CommandExec {
    static {
        try {
            Runtime.getRuntime().exec("open -a Calculator");
        } catch (IOException e) {

        }
    }
}
