package com.reajason.javaweb.integration;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

import java.util.List;

public class DoesNotContainExceptionMatcher extends TypeSafeMatcher<String> {

    /**
     * 已知无害的中间件启动噪音：
     * GlassFish 5.x 启动期 MEJBService 发布竞态（并发启动时更容易触发），与功能无关
     */
    private static final List<String> IGNORED_PATTERNS = List.of(
            "javax.naming.NoInitialContextException: Need to specify class name in environment"
    );

    public static DoesNotContainExceptionMatcher doesNotContainException() {
        return new DoesNotContainExceptionMatcher();
    }

    @Override
    protected boolean matchesSafely(String logs) {
        String filtered = logs;
        for (String ignored : IGNORED_PATTERNS) {
            filtered = filtered.lines()
                    .filter(line -> !line.contains(ignored))
                    .collect(java.util.stream.Collectors.joining("\n"));
        }
        return !filtered.contains("Exception: ") && !filtered.contains("Caused by:");
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("logs without exceptions");
    }

    @Override
    protected void describeMismatchSafely(String logs, Description mismatchDescription) {
        mismatchDescription.appendText("found logs containing exceptions:\n")
                .appendText(logs.replaceAll("(?m)^", "    "));
    }
}
