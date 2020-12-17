import java.net.ServerSocket;

public interface ForwardServerClientThread {
    public void run();
    public ServerSocket getListenSocket();
    public void connectionBroken();
}
