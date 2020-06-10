import java.io.Serializable;
import java.security.Key;

//Represents the object that is sended to the Peer by the Server //
public class AuthenticationResponse implements Serializable {
	
	private byte[] certificate;
	private Key publicKeyOfServer;

	public AuthenticationResponse(byte[] certificate, Key publicKeyOfServer)
	{
		this.certificate = certificate;
		this.setPublicKeyOfServer(publicKeyOfServer);

	}

	// GETTERS & SETTERS //
	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}

	public Key getPublicKeyOfServer() {
		return publicKeyOfServer;
	}

	public void setPublicKeyOfServer(Key publicKeyOfServer) {
		this.publicKeyOfServer = publicKeyOfServer;
	}
}
