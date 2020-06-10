import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Class That Handles Message Sending Operation Async //
public class PeerSenderThread extends Thread {
	
	private Socket serverSocket;
	private ObjectOutputStream objectOut;
	private HashMap<String, byte[]> mapOfKeys = new HashMap<String, byte[]>();
	private boolean terminateConnection;

	
	public PeerSenderThread(Socket serverSocket, HashMap<String, byte[]> mapOfKeys) throws IOException
	{
		this.serverSocket = serverSocket;
		this.objectOut = new ObjectOutputStream(this.serverSocket.getOutputStream());
		this.mapOfKeys = mapOfKeys;
		this.terminateConnection = false;
	}
	
	public void run()
	{
		System.out.print("");
		System.out.println("Write Your Message and Press Enter...");		
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
		try
		{
			terminateConnection = false;
			while(!terminateConnection)
			{
				// Reading Input Message //
				String messageToSend = bufferedReader.readLine();
				
				if(messageToSend.equals("Q"))
				{
					System.out.println("You Wanted To Terminate The Connection...");
					terminateConnection = true;
				}
				// Generating a HMAC //
				byte[] HMAC = generateHMAC(messageToSend);
				// Sending message and HMAC to the other peer //
				sendMessageToPeer(messageToSend, HMAC);
			}
			
		}catch(IOException e)
		{
			System.out.println("Error occured while sending message to peer!");
			System.err.println(e.getStackTrace());
		}
	}
	
	
	private void sendMessageToPeer(String messageToSend, byte[] HMAC)
	{
		// Encrypt the message text //
		byte[] encryptedMessage = encryptTheMessage(messageToSend);
		// Wrap encrypted message text and HMAC into Message object //
		Message message = new Message(encryptedMessage, HMAC);
		try {
			objectOut.writeObject(message);
			objectOut.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while sending message to another peer !");
		}
	}
	
	private byte[] encryptTheMessage(String messageToEncrypt)
	{
		byte[] encryptionKey = this.mapOfKeys.get("EncryptionKey");
		byte[] IV = this.mapOfKeys.get("InitializationVector");
		byte[] encryptedMessage = CryptoHelper.encryptMessage(encryptionKey, IV, messageToEncrypt);
		return encryptedMessage;
	}
	

	private byte[] generateHMAC(String messageToHash)
	{
		String algorithm = "HMACSHA512";
		byte[] HMAC = null;
		byte[] macKeyAsBytes = mapOfKeys.get("MacKey");
		// Regenerating The Mac Key From Bytes //
	    SecretKey regeneratedMacKey = new SecretKeySpec(macKeyAsBytes, 0, macKeyAsBytes.length, algorithm);
	    try {
	    	Mac mac = Mac.getInstance(algorithm);
	    	mac.init(regeneratedMacKey);
	    	HMAC = mac.doFinal(messageToHash.getBytes());
	    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return HMAC;
	}

	// GETTERS & SETTERS //
	public Socket getServerSocket() {
		return serverSocket;
	}

	public void setServerSocket(Socket serverSocket) {
		this.serverSocket = serverSocket;
	}

	public boolean isTerminateConnection() {
		return terminateConnection;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/*
	 * 		boolean hey = false;
	while(!hey)
	{
		sendMessageToPeer(bufferedReader);
		hey = true;
	}*/
	
	/*
	String message = "Hello Stalker !";
	try {
		dataOut.writeUTF(message);
		dataOut.flush();
		dataOut.close();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}*/
}
