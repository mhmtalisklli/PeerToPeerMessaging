import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Server {
	
	final static int SERVER_PORT_NO = 6066;
	private KeyPair keysOfServer;
	public static HashMap<String, Key> authorizedUsersCertificates = new HashMap<String, Key>();
	public static HashMap<String, Integer> connectedPeers = new HashMap<String, Integer>();
	
	public Server()	
	{}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Server server = new Server();
		
		server.setKeysOfServer(KeyGeneratorHelper.generateRSAKeys());
		server.executeServer();
	}
	
	private void executeServer()
	{
		ServerSocket serverSocket;
		try {
			serverSocket = new ServerSocket(SERVER_PORT_NO);
			System.out.println("Server's Executing Right Now..");
			while(true)
			{
				Socket socket = serverSocket.accept();
				// Server Thread Will Be Responsible To Authorize The Peers //
				new ServerThread(socket, this.keysOfServer).start();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while executing the server !");
		}
	}
	
	
	public KeyPair getKeysOfServer() {
		return keysOfServer;
	}

	public void setKeysOfServer(KeyPair keysOfServer) {
		this.keysOfServer = keysOfServer;
	}
}
