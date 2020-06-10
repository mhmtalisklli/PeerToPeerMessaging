import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Helper class to wrap encryption/decryption operations //

public class CryptoHelper {

	// Function To Encrypt The Public Key Of Connected Peer //
	public static byte[] rsaSigning(PrivateKey privateKey, byte[] informationToSign)
	{
		byte[] encryptedBytes = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			encryptedBytes = cipher.doFinal(informationToSign);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while signing the subpart !");
		}
		return encryptedBytes;
	}
	
	// Function To Encrypt Master Secret In Order To Send It To Other Peer //
	public static byte[] rsaEncryptionOfSecret(PrivateKey privateKey, SecretKey masterSecret)
	{
		byte[] encryptedBytes = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			encryptedBytes = cipher.doFinal(masterSecret.getEncoded());
			//System.out.println("Encryption Of Master Secret Was Successfull...");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while encrypting master secret !");
		}
		return encryptedBytes;

	}
	
	// Function To Encrypt The Generated Nonce //
	public static byte[] rsaEncryption(PrivateKey privateKey, byte[] nonceToEncrypt)
	{
		byte[] encryptedBytes = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			encryptedBytes = cipher.doFinal(nonceToEncrypt);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encryptedBytes;
	}
	
	// Function To Decrypt Encrypted Stuff //
	public static byte[] rsaDecryption(Key publicKey, byte[] dataToDecrypt)
	{
		Cipher cipher;
		byte[] decryptedBytes = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			decryptedBytes = cipher.doFinal(dataToDecrypt);
			//System.out.println("Decryption Is Successfull...");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error occured while decryption operation !");
		}
		return decryptedBytes;
	}
	
	// Function To Encrypt The Message With AES CBC Mode //
	public static byte[] encryptMessage(byte[] aesKey, byte[] initializationVector, String messageToEncrypt)
	{
		SecretKey key = new SecretKeySpec(aesKey, "AES"); //AES-128 key
		Cipher cipher;
		byte[] encryptedMessage = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initializationVector));
			//encryptedMessage = cipher.doFinal(messageToEncrypt.getBytes(StandardCharsets.UTF_8));
			encryptedMessage = cipher.doFinal(messageToEncrypt.getBytes());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encryptedMessage;
	}
	
	// Function To Decrypt The Message With AES CBC Mode //
	public static String decryptMessage(byte[] aesKey, byte[] initializationVector, byte[] encryptedMessage)
	{
		Cipher cipher;
		byte[] decryptedInputBytes = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(initializationVector);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);
			decryptedInputBytes = cipher.doFinal(encryptedMessage);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return new String(decryptedInputBytes);
	}
}
