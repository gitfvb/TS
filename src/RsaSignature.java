import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RsaSignature {

	// constants
	public final int length = 512;
	public final static String HASHFUNCTION = "SHA-256";
	public final BigInteger n;
	public final BigInteger e;
	public final String m;
	private final BigInteger privateKey; 
	
	/**
	 * Constructor of class to create primes and constants
	 * @param message message to encrypt
	 */
	public RsaSignature(String message) {
		// set constants
		m = message;
		
		SecureRandom rnd = new SecureRandom();
		
		// calculate n
		BigInteger p = BigInteger.probablePrime(length/2, rnd);
		BigInteger q = BigInteger.probablePrime(length/2, rnd);
		n = p.multiply(q);
		
		// calculate e
		// phi = (p-1)*(q-1);
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); 
		BigInteger eTemp;
		// calculate e until e is in amount of phi and gcd(phi,e) = 1
		do {
			eTemp = BigInteger.probablePrime(phi.bitLength(), rnd);
		} while (phi.gcd(eTemp).compareTo(BigInteger.ONE) != 0 || eTemp.compareTo(phi) > 0);
		e = eTemp;
				
		// calculate private key
		privateKey = e.modInverse(phi);
	}
	
	
	
	/**
	 * signs the saved message in the instance
	 * @return the encrypted hash of the message H(m)
	 * @throws NoSuchAlgorithmException
	 */
	public BigInteger signMessage() throws NoSuchAlgorithmException {
		// create hash
		String hash = createHash(m);
	
		// encrypt hash with private key (n,e)
		BigInteger c = new BigInteger(hash).modPow(privateKey, n);
		return c;
	}
	
	/**
	 * creates a hash
	 * @param s String to hash
	 * @return hashed String H(s)
	 * @throws NoSuchAlgorithmException
	 */
	private static String createHash(String s) throws NoSuchAlgorithmException {
		// creates the hash
		MessageDigest md;
		md = MessageDigest.getInstance(HASHFUNCTION);
		md.update(s.getBytes());
		byte byteData[] = md.digest();
					
		//convert the byte to hex format
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
        	sb.append(Integer.toString(byteData[i] & 0xff, 8));
        }
        return sb.toString();
	}
	
	/**
	 * decrypts the message
	 * @param c signature as a encrypted hash
	 * @return the decrypted hash
	 */
	public BigInteger decryptMessage(BigInteger c) {
		return c.modPow(e, n);
	}
	
	/**
	 * main-method
	 * @param args
	 */
	public static void main(String[] args) {
		
		try {
		
			// calculate
			String message = "91011121314151617181920212223242526272829";
			RsaSignature rsa = new RsaSignature(message);
			BigInteger signature = rsa.signMessage();
			String hashOfMessage = createHash(rsa.m);
			BigInteger decryptedSignature = rsa.decryptMessage(signature);
			
			// output results in console
			System.out.println("message : " + rsa.m);
			System.out.println("H(m) -> hash of m : " + hashOfMessage);
			System.out.println("n : " + rsa.n);
			System.out.println("e : " + rsa.e);
			System.out.println("signature / encryption of H(m) : " + signature.toString());
			System.out.println("decrypted signature : " + decryptedSignature.toString());
			System.out.println("Is H(m) and decrypted signature the same? " + hashOfMessage.contentEquals(decryptedSignature.toString()));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}
