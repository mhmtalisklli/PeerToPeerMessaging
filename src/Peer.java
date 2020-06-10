import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.InputMismatchException;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class Peer {

	final static int SERVER_PORT_NO = 6066;
	
	private String username;
	private int portNumber;
	private KeyPair keysOfUser;
	private boolean isAuthorized;
	private boolean terminateConnection;
	private SecretKey masterSecretKey;
	private byte[] randomNonce;
	private HashMap<String, byte[]> mapOfKeys = new HashMap<String, byte[]>();	// Includes Encryption Key, Mac Key and IV //
	public Peer(){
	}
	
	public static void main(String[] args) throws IOException {
		
		Peer peer = new Peer();
		peer.getInputValues();
		System.out.println();
		System.out.println("Communication Structure Is Building... Steps Succeded: 0/5");
		System.out.println();
		
		peer.keysOfUser = KeyGeneratorHelper.generateRSAKeys();

		System.out.println("Communication Structure Is Building... Steps Succeded: 1/5");
		System.out.println();
		// Connect To The Server //
		Socket socket = peer.connectToTheServer();
		// Check Server Connection Is Valid Or Not //
		boolean connectionValid = checkServerConnection(socket);
		if(!connectionValid) return;

		System.out.println("Communication Structure Is Building... Steps Succeded: 2/5");
		System.out.println();
		
		// Connection Was Checked, Now We Need To Make Authentication Request To The Server //
		// Authentication Request To Server //
		AuthenticationRequest authRequestMsg = new AuthenticationRequest
				(peer.getUsername(), peer.getPortNumber(), peer.getPublicKeyOfUser());
		AuthenticationResponse authResponseMsg = peer.makeAuthenticationRequest(authRequestMsg, socket);		
		// Verification Of The Certification //
		peer.verifyCertification(authResponseMsg);
		// Check Whether Peer Was Successfully Authorized Or Not. If Not; Then Terminate //
		if(!peer.isAuthorized) return;
		System.out.println("Communication Structure Is Building... Steps Succeded: 3/5");
		System.out.println();

		// Getting Information Of Other Peer That Was Connected To The Server (Port No, Username) //
		String[] targetPeerInfo = peer.getInformationOfOtherPeer(socket);
		// Generating Handshake Process Between Peers //
		HandshakeHandleThread handshakeHandleThread = null;

		peer.generateHandshakeHandler(handshakeHandleThread, targetPeerInfo[2], targetPeerInfo[1]);
		// Handshake Process Is Done, We Need To Generate Keys From Master Secret //		
		
		System.out.println("Communication Structure Is Building... Steps Succeded: 4/5");

		peer.keyGeneration();
		System.out.println("Key Generation Completed...");

		// Key Generation Is Done, Now Start Communication //
		// Peer Handler Executes The Server Process Of The Peer //
		PeerHandleThread peerHandle = peer.generatePeerHandler();
		
		System.out.println("Communication Structure Has Built... Steps Succeded: 5/5");
		
		// Now, Peers Will Try To Connect Each Other By Using Their Port Numbers //
		PeerReceiverThread peerReceiverThread = peer.startCommunication
												(targetPeerInfo[0], Integer.parseInt(targetPeerInfo[1]), peerHandle);
		// Handle Connection Closing //
		peer.endConnection(peerReceiverThread);
	}
	
	private void getInputValues()
	{
		boolean inputValid = false;
		while(!inputValid)
		{
			Scanner sc = new Scanner(System.in);
			System.out.println("Please Enter Your Username: ");
			this.username = sc.nextLine();
			System.out.println("Please Enter Your Port Number: ");
			try
			{
				this.portNumber = sc.nextInt();
				inputValid = true;
			}
			catch(InputMismatchException e)
			{
				System.out.println();
				System.out.println("You Should Enter A Valid Port Number !");
			}	
		}
	}
	
	private Socket connectToTheServer()
	{
		Socket socket = null;
		try {
			socket = new Socket("localhost", SERVER_PORT_NO);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while connecting to the server !");
			System.out.println("Server Is Not Online, It Should Be Executed First !");
		}
		return socket;
	}
	
	private static boolean checkServerConnection(Socket socket)
	{
		if(socket == null)
		{
			return false;
		}
		System.out.println("You Are Connected To Server Successfully...");
		return true;
	}
	
	private PeerHandleThread generatePeerHandler()
	{
		PeerHandleThread peerHandleThread = null;
		try {
			peerHandleThread = new PeerHandleThread(this.portNumber, this.mapOfKeys);
			peerHandleThread.start();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while generating peer handler !");
		}
		return peerHandleThread;
	}
	
	private void sendMessageToServer(Socket clientSocket, AuthenticationRequest authRequestMsg)
	{
		ObjectOutputStream objectOut;
		try {
			objectOut = new ObjectOutputStream(clientSocket.getOutputStream());
			objectOut.writeObject(authRequestMsg);
			objectOut.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while sending authentication request to the server !");
		}
	}

	private AuthenticationResponse getResponseFromServer(Socket clientSocket)
	{
		AuthenticationResponse authResponseMsg = null;
		try {
			ObjectInputStream objectIn = new ObjectInputStream(clientSocket.getInputStream());
			authResponseMsg = (AuthenticationResponse) objectIn.readObject();
		} catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while getting response from the server !");
		}
		return authResponseMsg;
	}
	
	private AuthenticationResponse makeAuthenticationRequest(AuthenticationRequest authRequestMsg, Socket socket)
	{
		AuthenticationResponse authResponseMsg = null;
		// Sending The Authentication Request With The Informations Of Peer //
		sendMessageToServer(socket, authRequestMsg);
		// Getting Back The Response From The Server //
		authResponseMsg = getResponseFromServer(socket);
		return authResponseMsg;
	}
	
	private void verifyCertification(AuthenticationResponse authResponseMsg)
	{
		byte[] certificate = authResponseMsg.getCertificate();
		byte[] subPart = new byte[certificate.length / 2];
		byte[] decryptedSubPart;
		byte[] decryptionResult = null;
		Key publicKeyOfServer = authResponseMsg.getPublicKeyOfServer();
		for(int i=0; i<2; i++)
		{
			if(i == 0)
			{
				System.arraycopy(certificate, 0, subPart, 0, subPart.length);
				decryptedSubPart = CryptoHelper.rsaDecryption(publicKeyOfServer, subPart);
				decryptionResult = new byte[decryptedSubPart.length * 2];
				decryptionResult = mergeDecryption(decryptionResult, decryptedSubPart, 1); 
			}
			else
			{
				System.arraycopy(certificate, subPart.length, subPart, 0, subPart.length);
				decryptedSubPart = CryptoHelper.rsaDecryption(publicKeyOfServer, subPart);
				decryptionResult = mergeDecryption(decryptionResult, decryptedSubPart, 2);
			}
		}
		
		if(new String(decryptionResult).equals(new String(this.getPublicKeyOfUser().getEncoded())))
		{
			System.out.println("Certification Was Verified...");
			this.isAuthorized = true;
		}
		else
		{
			System.out.println("Certification Couldn't Be Verified !");
			this.isAuthorized = false;
		}
	}
	
	private byte[] mergeDecryption(byte[] certificate, byte[] decryptedSubPart, int iteration)
	{
		if(iteration == 1)
		{
			System.arraycopy(decryptedSubPart, 0, certificate, 0, decryptedSubPart.length);
		}
		else
		{
			System.arraycopy(decryptedSubPart, 0, certificate, decryptedSubPart.length, decryptedSubPart.length);
		}
		return certificate;
	}
		
	private String[] getInformationOfOtherPeer(Socket clientSocket)
	{
		String permissionResult = "";
		String[] targetPeerInfo = null;
		try {
			DataInputStream dataIn = new DataInputStream(clientSocket.getInputStream());
			permissionResult = dataIn.readUTF();
			targetPeerInfo = permissionResult.split(":");
			dataIn.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return targetPeerInfo;
	}
	
	private PeerReceiverThread startCommunication(String targetPeerUsername, int portNumberOfTargetClient, PeerHandleThread peerHandle)
	{
		PeerReceiverThread peerReceiverThread = null;
		try {
			// Starting of Thread That Will Be Used To Send Messages To Other Peer //
			peerReceiverThread = new PeerReceiverThread(targetPeerUsername, portNumberOfTargetClient, this.mapOfKeys);
			peerReceiverThread.start();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		checkConnectionTerminate(peerReceiverThread, peerHandle);
		return peerReceiverThread;
	}
	
	private void generateHandshakeHandler(HandshakeHandleThread handshakeHandler, String peerStatus, String targetPortNumber)
	{
		Socket incomingSocket = null;
		ServerSocket handshakeSocket = null;
		if(peerStatus.equals("Initializer"))
		{
			//System.out.println("Peer Status Was Initializer");
			try {
				handshakeSocket = new ServerSocket(this.portNumber);
				System.out.println("Initializer Is Listening");
				incomingSocket = handshakeSocket.accept();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println();
		}
		
		else
		{
			//System.out.println("Peer Status Was Target");
			try {
				Thread.sleep(7000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				incomingSocket = new Socket("localhost", Integer.parseInt(targetPortNumber));
			} catch (NumberFormatException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	
		try {
			handshakeHandler = new HandshakeHandleThread(incomingSocket, this.keysOfUser, peerStatus);
			handshakeHandler.start();
		} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		System.out.println("Error occured while generating peer handler !");
		}
		
		while(handshakeHandler.isHandshakeDone() != true)
		{
			System.out.print("");
		}
		try {
			System.out.println("Handshake Process Successed...");
			this.masterSecretKey = handshakeHandler.getMasterSecret();
			this.randomNonce = handshakeHandler.getRandomNonce();
			incomingSocket.close();
			
			if(peerStatus.equals("Initializer"))
			{
				handshakeSocket.close();
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void keyGeneration()
	{
		// Generating Necessary Keys and IV By Using Master Secret From Handshaking Process //
		System.out.println();
		byte[] encryptionKey = KeyGeneratorHelper.generateEncryptionKey(this.masterSecretKey, this.randomNonce);
		byte[] macKey = KeyGeneratorHelper.generateMacKey(this.masterSecretKey);
	    byte[] initializationVector = KeyGeneratorHelper.generateInitializationVector(this.masterSecretKey, this.randomNonce);
		this.mapOfKeys.put("EncryptionKey", encryptionKey);
		this.mapOfKeys.put("MacKey", macKey);
		this.mapOfKeys.put("InitializationVector", initializationVector);
	}
	
	private void checkConnectionTerminate(PeerReceiverThread peerReceiverThread, PeerHandleThread peerHandleThread)
	{
		ConnectionOverThread connOverThread = new ConnectionOverThread(peerReceiverThread);
		while(peerReceiverThread.isTerminateConnection() != true || peerHandleThread.isTerminateConnection() != true)
		{
			if(peerReceiverThread.isTerminateConnection() == true || peerHandleThread.isTerminateConnection() == true)
			{
				return;
			}
			connOverThread.run();
		}
		this.terminateConnection = true;
	}
	
	private void endConnection(PeerReceiverThread peerReceiverThread)
	{
		try {
			System.out.println("Your Connection Has Terminated !");
			peerReceiverThread.getSocket().close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	// GETTERS & SETTERS //
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public PublicKey getPublicKeyOfUser()
	{
		return keysOfUser.getPublic();
	}

	public int getPortNumber() {
		return portNumber;
	}

	public boolean isAuthorized() {
		return isAuthorized;
	}
}
