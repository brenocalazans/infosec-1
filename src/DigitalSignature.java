import java.security.*;

public class DigitalSignature {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		
	    // verify args
	    if (args.length !=1) {
	      System.err.println("Usage: java DigitalSignatureExample text");
	      System.exit(1);
	    }
	    // get plain text
	    byte[] plainText = args[0].getBytes("UTF8");
	    
	    // generate RSA's key pair
	    System.out.println( "\nStart generating RSA key" );
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    KeyPair key = keyGen.generateKeyPair();
	    System.out.println( "Finish generating RSA key" );

	    // define signature object to use MD5 and RSA
	    // and sign the plain text with the private key,
	    // the used provider is also printed
	    Signature sig = Signature.getInstance("MD5WithRSA");
	    sig.initSign(key.getPrivate());
	    sig.update(plainText);
	    byte[] signature = sig.sign();
	    System.out.println( sig.getProvider().getInfo() );
	    System.out.println( "\nSignature:" );

	    // convert the signature to hex
	    StringBuffer buf = new StringBuffer();
	    for(int i = 0; i < signature.length; i++) {
	       String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF)).substring(1);
	       buf.append((hex.length() < 2 ? "0" : "") + hex);
	    }

	    // print the signature in hex
	    System.out.println( buf.toString() );

	    // verify the signature with the public key
	    System.out.println( "\nStart signature verification" );
	    sig.initVerify(key.getPublic());
	    sig.update(plainText);
	    try {
	      if (sig.verify(signature)) {
	        System.out.println( "Signature verified" );
	      } else System.out.println( "Signature failed" );
	    } catch (SignatureException se) {
	      System.out.println( "Singature failed" );
	    }
	}
}
