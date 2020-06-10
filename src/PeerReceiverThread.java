import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Class That Handles Message Receiving Operation Async //
public class PeerReceiverThread extends Thread{

	private Socket socket;
	//private DataInputStream dataIn;
	private ObjectInputStream objectIn;
	private String targetPeerUsername; 
	private HashMap<String, byte[]> mapOfKeys;
	private boolean terminateConnection;
	//private boolean connectionOver;
	
	public PeerReceiverThread(String targetPeerUsername, int targetClientPortNumber, HashMap<String, byte[]> mapOfKeys) throws IOException
	{
		socket = new Socket("localhost", targetClientPortNumber);
		this.targetPeerUsername = targetPeerUsername;
		this.objectIn = new ObjectInputStream(socket.getInputStream());
		this.mapOfKeys = mapOfKeys;
		this.terminateConnection = false;
	}
	
	public void run()
	{	
		try
		{	
			while(!terminateConnection)
			{
				// Thread Gets The Incoming Messages From The Other Peer //
				String incomingMessage = receiveTheIncomingMessage();
				if(incomingMessage.equals("Q"))
				{
					System.out.println(this.targetPeerUsername + " Wanted To Terminate Communication...");
					terminateConnection = true;
				}
				else
				{
					System.out.println("[" + this.targetPeerUsername + "]: " + incomingMessage);
				}
			}
		}catch(Exception e)
		{
			//System.err.println(e.getStackTrace());
			//System.out.println("Error occured in receiving process of message sent from other peer!");
		}
	}
	
	private String receiveTheIncomingMessage()
	{		
		Message incomingMessage;				// Message object that was sent from the other peer //
		byte[] encryptedMessageText = null;		// Encrypted version of the message sent //
		byte[] incomingHMAC = null;				// Incoming HMAC that was received together with encrypted message text //
		try {
			// Extracting the incoming stuff //
			incomingMessage = (Message) objectIn.readObject();
			encryptedMessageText = incomingMessage.getEncryptedMessage();
			incomingHMAC = incomingMessage.getHMAC();
		} catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			//System.out.println("Error occured while reading the message object !");
		}
		
		// Decrypt the incoming message text // 
		String decryptedMessageText = decryptTheEncryptedMessage(encryptedMessageText);
		
		// Generate a new HMAC in order to verify the incoming HMAC //
		byte[] verifierHMAC = generateHMAC(decryptedMessageText);
		// Verification Of Incoming HMAC //
		if(new String(verifierHMAC).equals(new String(incomingHMAC)))
		{
			return decryptedMessageText;
		}
		else
		{
			System.out.println("A Malicious Attack Was Detected !");
			System.out.println("You Should Refresh The Communication In Order To Continue!");
			terminateConnection = true;
			// Set Connection Over To True In Order To Terminate It //
			return decryptedMessageText;
		}
		

	}
		
	private String decryptTheEncryptedMessage(byte[] encryptedMessage)
	{
		byte[] encryptionKey = this.mapOfKeys.get("EncryptionKey");
		byte[] IV = this.mapOfKeys.get("InitializationVector");
		String incomingMessage = CryptoHelper.decryptMessage(encryptionKey, IV, encryptedMessage);
		return incomingMessage;
	}
	
	private byte[] generateHMAC(String messageToHash)
	{
		String algorithm = "HMACSHA512";
		byte[] HMAC = null;
		byte[] macKeyAsBytes = mapOfKeys.get("MacKey");
		// Regenerating The Mac Key From Bytes //
	    SecretKey regeneratedMacKey = new SecretKeySpec(macKeyAsBytes, 0, macKeyAsBytes.length, algorithm);
	    try {
	    	// Generating HMAC //
	    	Mac mac = Mac.getInstance(algorithm);
	    	mac.init(regeneratedMacKey);
	    	HMAC = mac.doFinal(messageToHash.getBytes());
	    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while generating HMAC !");
		}
	    return HMAC;
	}
	
	
	// GETTERS & SETTERS //
	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	public boolean isTerminateConnection() {
		return terminateConnection;
	}
	
	public void setTerminateConnection() {
		terminateConnection = true;
	}

}

