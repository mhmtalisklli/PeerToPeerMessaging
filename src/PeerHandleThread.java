import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

import javax.crypto.SecretKey;

// Class That Handles Message Sending Operation Async //
public class PeerHandleThread extends Thread {
	
	private ServerSocket serverSocket;
	private HashMap<String, byte[]> mapOfKeys = new HashMap<String, byte[]>();
	private boolean terminateConnection;
	
	public PeerHandleThread(int clientPortNumber, HashMap<String, byte[]> mapOfKeys) throws IOException

	{
		setServerSocket(new ServerSocket(clientPortNumber));
		this.mapOfKeys = mapOfKeys;
		this.terminateConnection = false;
	}
	
	public void run()
	{
		try {
			while(true)
			{
				Socket socket = serverSocket.accept();
				// Starting of Thread That Will Be Used To Send Messages //
				PeerSenderThread peerSenderThread = new PeerSenderThread(socket, this.mapOfKeys);
				peerSenderThread.start();
				checkConnectionTerminate(peerSenderThread);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	private void checkConnectionTerminate(PeerSenderThread peerSenderThread)
	{
		ConnectionOverThread connOverThread = new ConnectionOverThread(peerSenderThread);
		while(peerSenderThread.isTerminateConnection() != true)
		{
			connOverThread.run();
		}
		this.terminateConnection = true;
	}
	
	// GETTERS & SETTERS //
	public ServerSocket getServerSocket() {
		return serverSocket;
	}

	public void setServerSocket(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	public boolean isTerminateConnection() {
		return terminateConnection;
	}
}
