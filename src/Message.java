import java.io.Serializable;

// Wrapper class that represents the message sended/received between peers. //
public class Message implements Serializable{

	private byte[] encryptedMessage;
	private byte[] HMAC;
	
	
	public Message(byte[] encryptedMessage, byte[] HMAC)
	{
		this.encryptedMessage = encryptedMessage;
		this.HMAC = HMAC;
	}
	
	public byte[] getEncryptedMessage()
	{
		return this.encryptedMessage;
	}
	
	public byte[] getHMAC()
	{
		return this.HMAC;
	}
}













/*import java.io.Serializable;

public class PeerMessage implements Serializable{
	
	private String messageItself;
	private String usernameOfSender;
	
	public PeerMessage(String message, String username)
	{
		this.setMessageItself(message);
		this.setUsernameOfSender(username);
	}
	
	// GETTERS & SETTERS //
	public String getMessageItself() {
		return messageItself;
	}

	public void setMessageItself(String messageItself) {
		this.messageItself = messageItself;
	}

	public String getUsernameOfSender() {
		return usernameOfSender;
	}

	public void setUsernameOfSender(String usernameOfSender) {
		this.usernameOfSender = usernameOfSender;
	}
}
*/
