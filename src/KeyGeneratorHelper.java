import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import at.favre.lib.crypto.*;

// Helper class that wraps the rsa key, symmetric key, mac key, initialization vector generations //
public class KeyGeneratorHelper {
	
	public static KeyPair generateRSAKeys()
	{
		KeyPair keyPair = null;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			keyPair = generator.generateKeyPair();
			generator.initialize(2048);
			System.out.println("Key Pair Was Generated Successfully...");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("Error occured while generating key pairs !");
			e.printStackTrace();
		}
		return keyPair;
	}

	public static byte[] generateRandomNonce()
	{
		// Function of randomly generated 32 bytes nonce //
		SecureRandom secRan = new SecureRandom() ; 
		byte[] randomNonce = new byte[32] ;
		secRan.nextBytes(randomNonce);
		return randomNonce;
	}
	
	public static SecretKey generateMasterSecret()
	{
		final int KEY_SIZE = 256;
		KeyGenerator masterSecretKeyGenerator;
		SecretKey masterSecretKey = null;
		try {
			masterSecretKeyGenerator = KeyGenerator.getInstance("AES");
			masterSecretKeyGenerator.init(KEY_SIZE);
			masterSecretKey = masterSecretKeyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return masterSecretKey;
	}
	
	public static byte[] generateEncryptionKey(SecretKey masterKey, byte[] randomNonce)
	{
		HKDF hkdf = HKDF.fromHmacSha256();	// Key Derivation Function Class  //
		byte[] staticSalt32Byte = randomNonce;		
		byte[] masterKeyAsByteArray = masterKey.getEncoded();
		byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, masterKeyAsByteArray);
		byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
		//System.out.println("Encryption Key Was Generated...");
		return expandedAesKey;
	}
	
	public static byte[] generateMacKey(SecretKey masterKey)
	{
		SecretKey macKey = new SecretKeySpec(masterKey.getEncoded(), "HMAC_SHA512");
		return macKey.getEncoded();
	}
	
	public static byte[] generateInitializationVector(SecretKey masterKey, byte[] randomNonce)
	{		
		HKDF hkdf = HKDF.fromHmacSha256();
		byte[] staticSalt32Byte = randomNonce;
		byte[] masterKeyAsByteArray = masterKey.getEncoded();
		byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, masterKeyAsByteArray);
		byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);
		return expandedIv;
	}

}
