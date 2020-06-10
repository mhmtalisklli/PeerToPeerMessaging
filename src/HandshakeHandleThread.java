import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HandshakeHandleThread extends Thread{
	private Socket socket;
	private KeyPair keyPairOfPeer;
	private PublicKey publicKeyOfOtherPeer;
	private SecretKey masterSecret;
	private byte[] randomNonce;
	private String peerStatus;				// Initializer: User1; Target: User2 //
	private boolean handshakeDone;
	private ObjectInputStream objectIn;
	private ObjectOutputStream objectOut;
	
	public HandshakeHandleThread(Socket socket, KeyPair keyPairOfPeer, String peerStatus) throws IOException
	{
		this.setSocket(socket);
		this.setKeyPairOfPeer(keyPairOfPeer);
		this.setPeerStatus(peerStatus);
		this.setHandshakeDone(false);
		this.objectOut = new ObjectOutputStream(socket.getOutputStream());
		this.objectIn = new ObjectInputStream(socket.getInputStream());
	}

	public void run()
	{
		System.out.println();
		System.out.println("Handshake Started...");
		if(this.getPeerStatus().equals("Initializer"))
		{
			// If User Status Is Initializer; Which Represents The First Connected Peer //
			handshakeOfInitializer();
		}
		else
		{
			// If User Status Is Target; Which Represents The Second Connected Peer //
			handshakeOfTarget();
		}
	}

	private void handshakeOfInitializer()
	{
		// Process Of Initializer Peer //
		// 1- Initializer Sends a Hello Msg //
		HandshakeStuff handshakeStuff = generateHelloMsg();
		sendHandshakeStuff(handshakeStuff);
		//System.out.println("Hello Message And Public Key Were Sent From Initializer...");
		
		// 5- Initializer Receives Nonce And Public Key Of Target Peer //
		HandshakeStuff nonceAndPublicKey = getHandshakeStuff();
		//System.out.println("Nonce And Public Key Of Target Were Received By Initializer...");
		
		// 6- Initializer Stores The Public Key Of Target //
		this.publicKeyOfOtherPeer = nonceAndPublicKey.getPublicKeyOfPeer();
		
		// 7-8- Initializer Encrypts The Nonce, Sends It Back //
		//System.out.println("Incoming Nonce: " + nonceAndPublicKey.getRandomNonce());
		byte[] encryptedNonce = encryptNonce(nonceAndPublicKey.getRandomNonce());
		handshakeStuff = new HandshakeStuff(encryptedNonce);
		sendHandshakeStuff(handshakeStuff);
		//System.out.println("Encrypted Nonce Was Sent From Initializer...");

		// 12- Initializer Receives Ack //
		HandshakeStuff ackMessage = getHandshakeStuff();
		this.randomNonce = nonceAndPublicKey.getRandomNonce();
		//System.out.println("Ack Has Received...");
		
		// 13-14-15 Initializer Generates and Store A Master Secret, Encrypts It And Sends It //
		generateAndStoreMasterSecret();
		byte[] encryptedMasterSecret = encryptMasterSecret();
		handshakeStuff = new HandshakeStuff(encryptedMasterSecret);
		sendHandshakeStuff(handshakeStuff);
		//System.out.println("Encrypted Master Secret Was Sent From Initializer...");
		// Handshake Is Done For The Peer //
		this.handshakeDone = true;
	}
	
	private void handshakeOfTarget()
	{
		// Process Of Target Peer //
		// 2- Target Receives Hello Message //
		HandshakeStuff handshakeStuff = getHandshakeStuff();
		//System.out.println("Hello Message Was Received By Target...");	
		this.publicKeyOfOtherPeer = handshakeStuff.getPublicKeyOfPeer();
		
		
		// 3-4- Target Generates a Random Nonce And Sends It With His Public Key //
		byte[] randomNonce = generateRandomNonce();
		handshakeStuff = new HandshakeStuff(randomNonce, this.getKeyPairOfPeer().getPublic());
		sendHandshakeStuff(handshakeStuff);
		
		
		// 9- Target Receives Encrypted Nonce //
		HandshakeStuff encryptedNonce = getHandshakeStuff();
		//System.out.println("Encrypted Nonce Was Received By Target...");
		
		// TODO: 10-11 Target Decrypts The Nonce And Sends An Ack //
		byte[] decryptedNonce = CryptoHelper.rsaDecryption(this.publicKeyOfOtherPeer, encryptedNonce.getEncryptedNonce());
		boolean verificationResult = verifyNonce(randomNonce, decryptedNonce);
		
		if(verificationResult == false)	// If We Could Not Verify The Nonce; Then Handshake and Connection Will Be Terminated //
		{
			System.out.println("Nonce Couldn't Be Verified, Connection Is Not Allowed !");
			return;
		}
		else	// If We Could Verify; Then Continue //
		{
			this.randomNonce = decryptedNonce;
			//System.out.println("Nonce Was Verified...");
			
		}
		handshakeStuff = new HandshakeStuff("ACK MESSAGE");
		sendHandshakeStuff(handshakeStuff);
		//System.out.println("Ack Message Was Sent From Target...");

		// 16-17 Target Receives Master Secret, Decrypts And Store It //
		HandshakeStuff encryptedMasterSecret = getHandshakeStuff();
		this.masterSecret = decryptMasterSecret(encryptedMasterSecret.getEncryptedNonce());

		// Handshake Is Done For The Peer //
		this.handshakeDone = true;
	}
	
	private HandshakeStuff generateHelloMsg()
	{
		String helloMsg = "Hello Peer !";
		PublicKey publicKeyOfPeer = this.getKeyPairOfPeer().getPublic();
		HandshakeStuff handshakeStuff = new HandshakeStuff(helloMsg, publicKeyOfPeer);
		return handshakeStuff;
	}
	
	private void sendHandshakeStuff(HandshakeStuff handshakeStuff)
	{		
		try {
			objectOut.writeObject(handshakeStuff);
			objectOut.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while sending handshake stuff!");
		}
	}
	
	private HandshakeStuff getHandshakeStuff()
	{		
		HandshakeStuff handshakeStuff = null;
		try {
			handshakeStuff = (HandshakeStuff) objectIn.readObject();
		} catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while receiving handshake stuff!");
		}
		return handshakeStuff;
	}
	
	private byte[] encryptNonce(byte[] nonceToEncrypt)
	{
		byte[] encryptedNonce = CryptoHelper.rsaEncryption(this.getKeyPairOfPeer().getPrivate(), nonceToEncrypt);
		return encryptedNonce;
	}

	private byte[] generateRandomNonce()
	{
		byte[] randomNonce = KeyGeneratorHelper.generateRandomNonce();
		return randomNonce;
	}
	
	
	

	private boolean verifyNonce(byte[] randomNonce, byte[] decryptedNonce)
	{
		
		if(new String(randomNonce).equals(new String(decryptedNonce)))
		{
			return true;
		}
		return false;

	}
	
	private void generateAndStoreMasterSecret()
	{
		this.masterSecret = KeyGeneratorHelper.generateMasterSecret();
	}
	
	private byte[] encryptMasterSecret()
	{
		byte[] encryptedMasterSecret = CryptoHelper.rsaEncryptionOfSecret(this.keyPairOfPeer.getPrivate(), this.masterSecret);
		return encryptedMasterSecret;
	}
	
	private SecretKey decryptMasterSecret(byte[] encryptedMasterSecret)
	{
		byte[] decryptedMasterSecret = CryptoHelper.rsaDecryption(this.publicKeyOfOtherPeer, encryptedMasterSecret);
		// Rebuild Key using SecretKeySpec
		SecretKey originalMasterSecret = new SecretKeySpec(decryptedMasterSecret, 0, decryptedMasterSecret.length, "AES");		
		return originalMasterSecret;
	}
	

	
		
	// GETTERS & SETTERS //
	public KeyPair getKeyPairOfPeer() {
		return keyPairOfPeer;
	}

	public void setKeyPairOfPeer(KeyPair keyPairOfPeer) {
		this.keyPairOfPeer = keyPairOfPeer;
	}

	public String getPeerStatus() {
		return peerStatus;
	}

	public void setPeerStatus(String peerStatus) {
		this.peerStatus = peerStatus;
	}

	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	public boolean isHandshakeDone() {
		return handshakeDone;
	}

	public void setHandshakeDone(boolean handshakeDone) {
		this.handshakeDone = handshakeDone;
	}
	
	public SecretKey getMasterSecret() {
		return masterSecret;
	}

	public byte[] getRandomNonce() {
		return randomNonce;
	}
}
