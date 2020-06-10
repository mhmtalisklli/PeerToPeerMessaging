import java.io.Serializable;
import java.security.PublicKey;

// Wraps the informations that is flowed between peers in the handshaking process //
public class HandshakeStuff implements Serializable{

	private String helloMsg;
	private String ackMsg;
	private byte[] randomNonce;
	private byte[] encryptedNonce;
	private PublicKey publicKeyOfPeer;
	
	private byte[] certificate;

	public HandshakeStuff(String helloMsg, PublicKey publicKeyOfPeer)
	{
		this.setHelloMsg(helloMsg);
		this.setPublicKeyOfPeer(publicKeyOfPeer);
	}
	
	public HandshakeStuff(String helloMsg, byte[] certificate)
	{
		this.setHelloMsg(helloMsg);
		this.setCertificate(certificate);
	}

	
	public HandshakeStuff(byte[] randomNonce, PublicKey publicKeyOfPeer)
	{
		this.setRandomNonce(randomNonce);
		this.setPublicKeyOfPeer(publicKeyOfPeer);
	}
	
	public HandshakeStuff(String ackMsg)
	{
		this.setAckMsg(ackMsg);
	}
	
	public HandshakeStuff(byte[] encryptedNonce)
	{
		this.setEncryptedNonce(encryptedNonce);
	}

	public String getHelloMsg() {
		return helloMsg;
	}

	public void setHelloMsg(String helloMsg) {
		this.helloMsg = helloMsg;
	}

	public String getAckMsg() {
		return ackMsg;
	}

	public void setAckMsg(String ackMsg) {
		this.ackMsg = ackMsg;
	}

	public byte[] getRandomNonce() {
		return randomNonce;
	}

	public void setRandomNonce(byte[] randomNonce) {
		this.randomNonce = randomNonce;
	}

	public PublicKey getPublicKeyOfPeer() {
		return publicKeyOfPeer;
	}

	public void setPublicKeyOfPeer(PublicKey publicKeyOfPeer) {
		this.publicKeyOfPeer = publicKeyOfPeer;
	}

	public byte[] getEncryptedNonce() {
		return encryptedNonce;
	}

	public void setEncryptedNonce(byte[] encryptedNonce) {
		this.encryptedNonce = encryptedNonce;
	}

	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}
	
}
