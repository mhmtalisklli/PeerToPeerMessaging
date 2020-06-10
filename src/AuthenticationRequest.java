import java.io.Serializable;
import java.security.Key;

// Represents the object that is sended to the Server by the Peer, contains information of Peer //
public class AuthenticationRequest implements Serializable {
	private String username;
	private int portNumberOfPeer;
	private Key publicKeyOfUser;
	
	AuthenticationRequest(String username, int portNumberOfPeer, Key publicKeyOfUser)
	{
		this.setUsername(username);
		this.setPortNumberOfPeer(portNumberOfPeer);
		this.setPublicKeyOfUser(publicKeyOfUser);
	}

	// GETTERS & SETTERS //
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public Key getPublicKeyOfUser() {
		return publicKeyOfUser;
	}
	public void setPublicKeyOfUser(Key publicKeyOfUser) {
		this.publicKeyOfUser = publicKeyOfUser;
	}

	public int getPortNumberOfPeer() {
		return portNumberOfPeer;
	}

	public void setPortNumberOfPeer(int portNumberOfPeer) {
		this.portNumberOfPeer = portNumberOfPeer;
	}
}
