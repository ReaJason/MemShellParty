import jakarta.websocket.*;
import jakarta.websocket.server.ServerEndpoint;

import java.io.IOException;
import java.util.logging.Logger;

@ServerEndpoint("/ws/demo")
public class EmptyWebSocketEndpoint {

    private static final Logger logger = Logger.getLogger(EmptyWebSocketEndpoint.class.getName());

    @OnOpen
    public void onOpen(Session session) {
        logger.info("New connection established: " + session.getId());
        try {
            // 向客户端发送欢迎消息
            session.getBasicRemote().sendText("Connected successfully! Session ID: " + session.getId());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @OnMessage
    public void onMessage(String message, Session session) {
        logger.info("Received message from " + session.getId() + ": " + message);
        try {
            session.getBasicRemote().sendText("Server Echo: " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @OnClose
    public void onClose(Session session, CloseReason closeReason) {
        logger.info("Session closed: " + session.getId() + ", Reason: " + closeReason.getReasonPhrase());
    }

    @OnError
    public void onError(Session session, Throwable throwable) {
        logger.severe("Error on session " + (session != null ? session.getId() : "null") + ": " + throwable.getMessage());
    }
}
