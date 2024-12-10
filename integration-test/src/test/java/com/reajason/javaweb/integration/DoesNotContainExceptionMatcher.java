package com.reajason.javaweb.integration;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class DoesNotContainExceptionMatcher extends TypeSafeMatcher<String> {

    @Override
    protected boolean matchesSafely(String logs) {
        return !logs.contains("Exception");
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

    public static DoesNotContainExceptionMatcher doesNotContainException() {
        return new DoesNotContainExceptionMatcher();
    }
}
