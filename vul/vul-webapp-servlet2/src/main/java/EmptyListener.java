import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

public class EmptyListener implements ServletRequestListener {
    @Override
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
        ServletRequest servletRequest = servletRequestEvent.getServletRequest();
    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        ServletRequest servletRequest = servletRequestEvent.getServletRequest();
    }
}
