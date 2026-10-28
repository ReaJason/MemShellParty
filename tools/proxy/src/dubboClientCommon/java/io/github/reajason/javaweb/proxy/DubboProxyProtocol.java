package io.github.reajason.javaweb.proxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

final class DubboProxyProtocol {

    private static final int CREATE = 0;
    private static final int PUSH = 1;
    private static final int PULL = 2;
    private static final int CLOSE = 3;
    private static final int SHUTDOWN_OUTPUT = 4;

    private DubboProxyProtocol() {
    }

    static byte[] createRequest() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeByte(CREATE);
        output.flush();
        return bytes.toByteArray();
    }

    static byte[] pushRequest(String token, byte[] payload, int length) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(length + 16);
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeByte(PUSH);
        output.writeUTF(token);
        output.writeInt(length);
        output.write(payload, 0, length);
        output.flush();
        return bytes.toByteArray();
    }

    static byte[] pullRequest(String token) throws IOException {
        return tokenRequest(PULL, token);
    }

    static byte[] closeRequest(String token) throws IOException {
        return tokenRequest(CLOSE, token);
    }

    static byte[] shutdownOutputRequest(String token) throws IOException {
        return tokenRequest(SHUTDOWN_OUTPUT, token);
    }

    private static byte[] tokenRequest(int operation, String token) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeByte(operation);
        output.writeUTF(token);
        output.flush();
        return bytes.toByteArray();
    }

    static String parseCreateResponse(byte[] response) throws IOException {
        DataInputStream input = responseInput(response);
        checkStatus(input);
        return input.readUTF();
    }

    static void parseOkResponse(byte[] response) throws IOException {
        checkStatus(responseInput(response));
    }

    static PullResponse parsePullResponse(byte[] response) throws IOException {
        DataInputStream input = responseInput(response);
        checkStatus(input);
        int length = input.readInt();
        if (length == -1) {
            return new PullResponse(-1, null);
        }
        if (length == 0) {
            return new PullResponse(0, null);
        }
        if (length < 0) {
            throw new IOException("Invalid Dubbo proxy payload length: " + length);
        }
        byte[] payload = new byte[length];
        input.readFully(payload);
        return new PullResponse(length, payload);
    }

    private static DataInputStream responseInput(byte[] response) throws IOException {
        if (response == null) {
            throw new IOException("Dubbo proxy returned a null response");
        }
        return new DataInputStream(new ByteArrayInputStream(response));
    }

    private static void checkStatus(DataInputStream input) throws IOException {
        int status = input.readUnsignedByte();
        if (status != 0) {
            throw new IOException("Dubbo proxy error: " + input.readUTF());
        }
    }

    static final class PullResponse {
        final int length;
        final byte[] payload;

        PullResponse(int length, byte[] payload) {
            this.length = length;
            this.payload = payload;
        }
    }
}
