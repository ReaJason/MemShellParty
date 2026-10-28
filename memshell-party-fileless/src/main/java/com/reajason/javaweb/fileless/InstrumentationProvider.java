package com.reajason.javaweb.fileless;

import java.lang.instrument.Instrumentation;

public interface InstrumentationProvider {
    Instrumentation acquire() throws Exception;
}
