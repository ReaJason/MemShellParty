package com.reajason.javaweb.probe.payload;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2025/11/18
 */
class ScriptEngineProbeTest {

    @Test
    void test(){
        String hello = new ScriptEngineProbe("1 + 1").toString();
        assertEquals("2", hello);
    }
}