package com.reajason.javaweb.probe.payload;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2025/8/26
 */
class CommandProbeTest {

    @Test
    @Disabled
    void test() {
        String result = new CommandProbe("hello").toString();
        assertThat(result, anyOf(
                containsString("not found")
        ));
    }
}