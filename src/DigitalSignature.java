import org.apache.commons.codec.binary.Hex;

import java.security.*;

public class DigitalSignature {

	public static final String ENCODING = "UTF-8";

	public static MessageDigest getMD5() throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("MD5");
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		MessageDigest md5;
		byte[] plainText, digest;

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
		System.out.println("\nDigest(hex): " + Hex.encodeHexString(digest));

		// generate RSA's key pair
		System.out.println("\nStart generating RSA key");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println("Finish generating RSA key");

		// define signature object to use MD5 and RSA
		// and sign the plain text with the private key,
		// the used provider is also printed
		MySignature sig = MySignature.getInstance("MD5WithRSA");
		sig.initSign(key.getPrivate());
		sig.update(plainText);
		byte[] signature = sig.sign();
		System.out.println("\nSignature:");

		// print the signature in hex
		System.out.println(Hex.encodeHexString(signature));

		// verify the signature with the public key
		System.out.println("\nStart signature verification");
		sig.initVerify(key.getPublic());
		sig.update(plainText);
		try {
			if (sig.verify(signature)) {
				System.out.println("Signature verified");
			} else System.out.println("Signature failed");
		} catch (SignatureException se) {
			System.out.println("Singature failed");
		}
	}
}

class MySignature {

	public static MySignature getInstance(String md5WithRSA) {
		return new MySignature();
	}

	public void initSign(PrivateKey aPrivate) {
	}

	public void update(byte[] plainText) {
	}

	public byte[] sign() {
		return new byte[0];  //To change body of created methods use File | Settings | File Templates.
	}

	public void initVerify(PublicKey aPublic) {
		//To change body of created methods use File | Settings | File Templates.
	}

	public boolean verify(byte[] signature) throws SignatureException {
		return false;  //To change body of created methods use File | Settings | File Templates.
	}
}