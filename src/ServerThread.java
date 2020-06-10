import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.text.html.HTMLDocument.Iterator;

public class ServerThread extends Thread{

	private ObjectInputStream dataIn;
	private ObjectOutputStream dataOut;
	private Socket serverSocket;
	private KeyPair keysOfServer;
	
	private DataOutputStream outputStream;
	
	
	public ServerThread(Socket serverSocket, KeyPair keysOfServer) throws IOException
	{
		this.setServerSocket(serverSocket);
		this.keysOfServer = keysOfServer;
		this.setDataIn(new ObjectInputStream(serverSocket.getInputStream()));
		this.setDataOut(new ObjectOutputStream(serverSocket.getOutputStream()));
		this.outputStream = new DataOutputStream(serverSocket.getOutputStream());
	}
	
	public void run()
	{
		try
		{
			System.out.println("Client Has Successfully Connected To The Server...");
			System.out.println();
			while(true)
			{
				// Getting Authentication Request From The Peer //
				AuthenticationRequest userMsg = (AuthenticationRequest) dataIn.readObject();
				System.out.println("Authentication Request Was Received By The Server..." + "[" + userMsg.getUsername() +"]");
				// Generating Certificate By Encrypting The Public Key Of Peer //
				byte[] certificate = generateCertificate(userMsg); 
				appendPeerToConnectionMap(userMsg);
				// Generate An Authentication Response Message //
				AuthenticationResponse certificateMsg = new AuthenticationResponse(certificate, this.keysOfServer.getPublic());
				sendAuthResponseToPeer(certificateMsg);
				System.out.println("Authentication Response Was Sent To The User..." + "[" + userMsg.getUsername() +"]");
				System.out.println();
				// We Need To Wait Until One More Peer To Be Connected To The Server In Order To Communicate //
				waitForOtherUserToBeAvailable();
				sendAvailabilityMessageToPeer(userMsg);
				
	
				
			}
		}
		catch(IOException | ClassNotFoundException e)
		{
			System.out.println("Error occured while getting request from client !");
			System.err.println(e.getStackTrace());
		}
		finally
		{
			try {
				dataOut.close();
				dataIn.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.out.println("Error occured while closing the streams !");
			}
		}
	}
	
	
	// Function generates the certificate by signing the data with signature //
	private byte[] generateCertificate(AuthenticationRequest authRequestMsg)
	{
		// Extracting The Incoming Values //
		Key publicKeyOfPeer = authRequestMsg.getPublicKeyOfUser();
		String usernameOfPeer = authRequestMsg.getUsername();
		int portNumberOfPeer = authRequestMsg.getPortNumberOfPeer();

		byte[] encryptedSubPart = null;
		byte[] informationToEncryptAsBytes = publicKeyOfPeer.getEncoded();
		byte[] certificate = new byte[512];

		// Since The Data Is Huge To Encrypt With AES Private Key Of Server; We Split It Into Two Parts //
		int counter = 0;
		int iteration = 1;
		byte[] subPart = new byte[informationToEncryptAsBytes.length / 2];
		for(byte b : informationToEncryptAsBytes)
		{
			subPart[counter] = b;
			if(counter == informationToEncryptAsBytes.length / 2 - 1)
			{
				encryptedSubPart = encryptTheSubPartOfInformation(subPart);
				certificate = mergeEncryption(certificate, encryptedSubPart, iteration);
				counter = -1;
				subPart = new byte[informationToEncryptAsBytes.length / 2];
				iteration++;
			}
			counter++;
		}
		// Once We Generated Certificate, We Add The Peer' Certificate To The Server's HashMap In Order To Store //
		Server.authorizedUsersCertificates.put(usernameOfPeer, publicKeyOfPeer);
		System.out.println("Certification Was Completed... [" + usernameOfPeer + "]");
		return certificate;
	}
	
	private byte[] mergeEncryption(byte[] certificate, byte[] encryptedSubPart, int iteration)
	{
		if(iteration == 1)
		{
			System.arraycopy(encryptedSubPart, 0, certificate, 0, encryptedSubPart.length);
		}
		else
		{
			System.arraycopy(encryptedSubPart, 0, certificate, encryptedSubPart.length, encryptedSubPart.length);
		}
		return certificate;
	}
	
	private byte[] encryptTheSubPartOfInformation(byte[] subPartOfInformation)
	{
		byte[] encryptedInformation = null;
		encryptedInformation = CryptoHelper.rsaSigning(keysOfServer.getPrivate(), subPartOfInformation);
		return encryptedInformation;
		
	}

	private static void appendPeerToConnectionMap(AuthenticationRequest authRequestMsg) 
	{
		String username = authRequestMsg.getUsername();
		int portNumberOfPeer = authRequestMsg.getPortNumberOfPeer();
		Server.connectedPeers.put(username, portNumberOfPeer);
		System.out.println("Peer: " + username + " Was Added To ConnectionMap");
	}
	
	private void sendAuthResponseToPeer(AuthenticationResponse certificateMsg)
	{
		try {
			dataOut.writeObject(certificateMsg);
			dataOut.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while sending authentication response to the peer !");
		}
	}
	
	private void waitForOtherUserToBeAvailable()
	{
		// We Need To Wait For Connection Of Other Peer /
		while(Server.connectedPeers.size() < 2)
		{
			try {
				Thread.sleep(7000);
				System.out.println("There Are Nobody To Connect, Will Be Checked In 7 Sec. Please Wait...");
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		System.out.println("Someone Connected, You're Matched With Him Right Now...");
	}
		
	private void sendAvailabilityMessageToPeer(AuthenticationRequest authRequestMsg)
	{
		String username = "";
		String portNumber = "";
		String usernameToSend = "";
		String portNoToSend = "";
		String statusToSend = "Initializer";
		String information = "";
		int counter = 0;
		for(Map.Entry<String, Integer> connection : Server.connectedPeers.entrySet())
		{
			username = connection.getKey();
			portNumber = connection.getValue().toString();
			if(username != authRequestMsg.getUsername())
			{
				
				usernameToSend = username;
				portNoToSend = portNumber;
				
				if(counter == 0)
				{
					statusToSend = "Target";
				}
				
				information = usernameToSend + ":" + portNoToSend + ":" + statusToSend;
			}
			counter++;
		}
		
		try {
			this.outputStream.writeUTF(information);
			outputStream.flush();
			outputStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while sending availability message to the peer !");
		}
	}
	
	
	// GETTERS & SETTERS //
	public ObjectOutputStream getDataOut() {
		return dataOut;
	}

	public void setDataOut(ObjectOutputStream dataOut) {
		this.dataOut = dataOut;
	}
	
	public ObjectInputStream getDataIn() {
		return dataIn;
	}

	public void setDataIn(ObjectInputStream dataIn) {
		this.dataIn = dataIn;
	}
	
	public Socket getServerSocket() {
		return serverSocket;
	}

	public void setServerSocket(Socket serverSocket) {
		this.serverSocket = serverSocket;
	}
}




















/*
if(Server.connectedPeers.size() < 2)
{
	System.out.println("CHECK FAILED !");
	Thread.sleep(7000);
}

if(Server.connectedPeers.size() == 2)
{
	System.out.println("CHECK SUCCESS !");
	outputStream.writeUTF("Connection Allowed !");
	outputStream.flush();
	System.out.println("Connection Allowed to The User..." + "[" + userMsg.getUsername() +"]");
}
*/
