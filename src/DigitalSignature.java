import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Arrays;

public class DigitalSignature {

	public static final String ENCODING = "UTF-8";

	public static MessageDigest getMD5() throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("MD5");
	}
	
	public static String encodeHexString(byte[] str) {
		StringBuffer buf = new StringBuffer();
	    for(int i = 0; i < str.length; i++) {
	       String hex = Integer.toHexString(0x0100 + (str[i] & 0x00FF)).substring(1);
	       buf.append((hex.length() < 2 ? "0" : "") + hex);
	    }
	    return buf.toString();
	}
	

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		MessageDigest md5;
		byte[] plainText, digest, signature;
		KeyPairGenerator keyGen;
		KeyPair key;
		MySignature mySignature;
		String verificationSuccess = "Signature verified";
		String verificationFail = "Signature verification failed";

		// verify args
		if (args.length != 1) {
			System.err.println("Usage: java DigitalSignatureExample text");
			System.exit(1);
		}
		// get plain text
		plainText = args[0].getBytes(ENCODING);

		// get a message digest object using the MD5 algorithm
		md5 = getMD5();

		// calculate the digest and print it out
		md5.update(plainText);
		digest = md5.digest();

		System.out.println("\n" + md5.getProvider().getInfo());
		System.out.println("\nDigest length: " + digest.length * 8 + "bits");
		System.out.println("\nDigest(hex): " + encodeHexString(digest));

		// generate RSA's key pair
		System.out.println("\nStart generating RSA key");
		keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		key = keyGen.generateKeyPair();
		System.out.println("Finish generating RSA key");
		
		// sign
		mySignature = MySignature.getInstance();
		mySignature.initSign(key.getPrivate());
		mySignature.update(plainText);
		signature = mySignature.sign();
		System.out.println("\nSignature:");
		System.out.println(encodeHexString(signature));

		// verify the signature with the public key
		System.out.println("\nStart signature verification");
		mySignature.initVerify(key.getPublic());
		mySignature.update(plainText);

		// report signature verification
		try {
			System.out.println(mySignature.verify(signature) ? verificationSuccess : verificationFail);
		} catch (SignatureException se) {
			System.out.println(verificationFail);
		}
	}
}

// custom implementation of Signature class
class MySignature {

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private byte[] text;

	public static MySignature getInstance() {
		return new MySignature();
	}

	public void initSign(PrivateKey aPrivate) {
		privateKey = aPrivate;
	}

	public void update(byte[] plainText) {
		text = plainText;
	}

	public byte[] sign() {
		byte[] digest, signature;
		Cipher cipher;
		MessageDigest md5;
		try {			
			// get digest
			md5 = DigitalSignature.getMD5();
			md5.update(text);
			digest = md5.digest();
			System.out.println("MYSIG - MD5 Hashed text: " + DigitalSignature.encodeHexString(digest));
			
			// initializing cipher
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			System.out.println("MYSIG - Cipher provider: " + cipher.getProvider().getInfo());
			// encrypting using private key
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			System.out.println("MYSIG - Using private key: " + DigitalSignature.encodeHexString(privateKey.getEncoded()));
			// finally sign
			signature = cipher.doFinal(digest);
			System.out.println("MYSIG - Hashed text encrypted by private key: " + DigitalSignature.encodeHexString(signature));
			
			return signature;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No MD5 available. Can't sign!");
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("Padding not available. Can't sign!");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key. Can't sign!");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("Bad padding. Can't sign!");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Illegal block size. Can't sign!");
			e.printStackTrace();
		}

		return new byte[0];
	}

	public void initVerify(PublicKey aPublic) {
		publicKey = aPublic;
	}

	public boolean verify(byte[] signature) throws SignatureException {
		byte[] digest, decryptedDigest;
		Cipher cipher;
		MessageDigest md5;
		try {
			// get digest
			md5 = DigitalSignature.getMD5();
			md5.update(text);
			digest = md5.digest();
			System.out.println("MYSIG - MD5 Hashed text: " + DigitalSignature.encodeHexString(digest));
			
			// initializing cipher
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			System.out.println("MYSIG - Cipher provider: " + cipher.getProvider().getInfo());
			// decrypting using public key
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			System.out.println("MYSIG - Using public key: " + DigitalSignature.encodeHexString(publicKey.getEncoded()));
			// decrypt using signature
			decryptedDigest = cipher.doFinal(signature);
			System.out.println("MYSIG - Using signature: " + DigitalSignature.encodeHexString(signature));
			System.out.println("MYSIG - Decrypted MD5 Hash: " + DigitalSignature.encodeHexString(decryptedDigest));
			
			// return boolean verification
			return Arrays.equals(digest, decryptedDigest);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No MD5 available. Can't sign!");
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("Padding not available. Can't sign!");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key. Can't sign!");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("Bad padding. Can't sign!");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Illegal block size. Can't sign!");
			e.printStackTrace();
		}
		return false;
	}
}