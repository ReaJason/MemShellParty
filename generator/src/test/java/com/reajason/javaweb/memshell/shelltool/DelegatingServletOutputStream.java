package com.reajason.javaweb.memshell.shelltool;

import javax.servlet.ServletOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class DelegatingServletOutputStream extends ServletOutputStream {
    private final ByteArrayOutputStream delegate;

    public DelegatingServletOutputStream(ByteArrayOutputStream delegate) {
        this.delegate = delegate;
    }

    @Override
    public void write(int b) throws IOException {
        delegate.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        delegate.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        delegate.write(b, off, len);
    }
}