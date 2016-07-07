/**
 * EncryptionZKP.java
 */
package paillierp.zkp;

import java.math.BigInteger;

import paillierp.AbstractPaillier;
import paillierp.ByteUtils;
import paillierp.key.*;

/**
 * A non-interactive Zero Knowledge Proof that the ciphertext is of a
 * known message.  This Zero Knowledge Proof correctly proves that one knows
 * the plaintext <i>m</i> and random number <i>r</i> in the ciphertext
 * <I>E</i>(<i>m</i>, <i>r</i>).  This is done without revealing either the
 * plaintext nor the random number. 
 * <p>
 * The protocol is given on p. 41 in <i>Multiparty Computation from
 * Threshold Homomorphic Encryption</i> by Cramer, Damg&aring;rd, and
 * Nielsen.
 * 
 * @author Murat Kantarcioglu
 * @author Sean Hall
 * @author James Garrity
 */
public class EncryptionZKP extends ZKP {

	/*
	 * 
	 * Fields
	 * 
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = 6683900023178557008L;
	
	private BigInteger nSPlusOne;
	
	private BigInteger n;
	
	/**
	 * <i>us<sup>e</sup>g<sup>t</sup></i> mod <i>n</i><sup>2</sup> for 
	 * hash <i>e</i> and <i>g=n</i>+1.
	 */
	private BigInteger z;
	
	/**
	 * The value <i>x+e&alpha;</i> for the plaintext <i>&alpha;</i> and
	 * random <i>x</i>.
	 */
	private BigInteger w;
	
	/**
	 * <i>g<sup>x</sup>u<sup>n</sup></i> mod <i>n</i><sup>2</sup> 
	 * for random <i>x, u</i>.
	 */
	private BigInteger b;
	
	/**
	 * Ciphertext <i>E</i>(<i>&alpha;</i>, <i>r</i>).
	 */
	private BigInteger c;

	/*
	 * 
	 * Constructors
	 * 
	 */
	
	/**
	 * Creates an instance of the Zero Knowledge Proof of decryption from a
	 * byte array which <b>does</b> have the key encoded.
	 * 
	 * @param b		byte array of the necessary values for a ZKP
	 * 
	 * @throws IllegalArgumentException if it detects that some corruption has
	 * 					occured, for example, if the "size of next BigInteger"
	 * 					field is a larger number than typical causing out of
	 * 					bounds issues.
	 * 
	 * @see #toByteArray()
	 */
	public EncryptionZKP(byte[] b) {
		//TODO error if b.length = 0
		try{
			int offset = 0;
			
			int size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.c = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.b = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.w = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.z = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.nSPlusOne = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.n = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
		} catch(ArrayIndexOutOfBoundsException e) {
			throw new IllegalArgumentException("byte input corrupted or incomplete");
		}
	}
	
	/**
	 * Creates an instance of the Zero Knowledge Proof from a byte array
	 * (which does not have the key) and the values necessary for verification.
	 * If the key values were originally encoded into {@code b}, then
	 * <i>those</i> values are used.
	 * 
	 * @param b			byte array of the necessary values for a ZKP
	 * @param nSPlusOne	the public key modulus <i>n<sup>s+1</sup></i>
	 * @param n			the public key modulus <i>n</i>
	 * 
	 * @see #toByteArrayNoKey()
	 */
	public EncryptionZKP(byte[] b, BigInteger nSPlusOne, BigInteger n) {
		this(ByteUtils.appendBigInt(b, nSPlusOne, n));
		// Even if b was created with toByteArray, it would simply
		// have nSPlusOne, v, and vi listed twice.
	}
	
	/**
	 * Creates an instance of the Zero Knowledge Proof from a byte array
	 * (which does <b>not</b> have the key) and a public key.  If the key
	 * values were originally encoded into {@code b}, then <i>those</i>
	 * values are used.
	 * 
	 * @param b			byte array of the necessary values for a ZKP
	 * @param pubkey	public Paillier key to provide further recurring
	 * 					values for a ZKP
	 * 
	 * @see #toByteArrayNoKey()
	 */
	public EncryptionZKP(byte[] b, PaillierKey pubkey) {
		this(b,pubkey.getNSPlusOne(), pubkey.getN());
	}
	
	/**
	 * Computes a random encryption of {@code alpha}.  This additionally sets up
	 * a Zero Knowledge Proof that this multiplication was done, without
	 * revealing anything of {@code alpha}.
	 * 
	 * @param key       Public key <i>n</i> used to encrypt
	 * @param alpha     The message &alpha;
	 */
	public EncryptionZKP(PaillierKey key, BigInteger alpha) {
		if(!key.inModN(alpha)) {
			throw new IllegalArgumentException("alpha must be 0 <= alpha < n");
		}
		BigInteger c=null;
		BigInteger s=null;
		BigInteger x=null;
		BigInteger u=null;
		BigInteger b=null;
		BigInteger e=null;
		BigInteger w=null;
		BigInteger t=null;
		BigInteger z=null;
		
		BigInteger dummy=null;
		BigInteger n = key.getN();
		BigInteger nPlusOne = key.getNPlusOne();
		BigInteger nSquare = key.getNSPlusOne();
	    
        //c (C_alpha in the paper) is basically the encryption of alpha
		//s is the randomness required
		s = key.getRandomModNStar();
		
		// calculate s^n mod nSquare 	
		//calculate (1+n)^alpha*(s^n) mod n^2
		//c=((nPlusOne.modPow(alpha,nSquare)).multiply(s.modPow(n,nSquare))).mod(nSquare);
		c = AbstractPaillier.encrypt(alpha, s, key);
		
		//x is a random element from Z_N
		x = key.getRandomModN();
		
		// we need to find an u in $Z^*_{N^2}$
		u = key.getRandomModNSPlusOneStar();

		b=((nPlusOne.modPow(x,nSquare)).multiply(u.modPow(n,nSquare))).mod(nSquare);
		
		// Calculate the Hash function to create random choice e
		e = hash(c.toByteArray(), b.toByteArray());
		
		//w=x+e*alpha mod N
		dummy=x.add(e.multiply(alpha));
		w=dummy.mod(n);
		t=dummy.divide(n);

		//$z=u.s^e.(1+n)^t$
		z=((u.multiply(s.modPow(e,nSquare))).multiply(nPlusOne.modPow(t,nSquare))).mod(nSquare);
		
		this.c=c;
		this.b=b;
		this.w=w;
		this.z=z;
		this.n=key.getN();
		this.nSPlusOne=key.getNSPlusOne();
		
		//System.out.println("Encrypting "+alpha+" to "+c);
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * The encrypted value of &alpha;.
	 */
	public BigInteger getValue() {
		return c;
	}

	/**
	 * Verifies if all of the above integers are indeed true, thereby showing 
	 * that this encryption is exact.
	 * 
	 * @return     True if the computed value is indeed a random encryption
	 *             of a known message
	 */
	public boolean verify() {
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		BigInteger e = hash(c.toByteArray(), b.toByteArray());
		
		try {
			return ((((nPlusOne.modPow(w,nSPlusOne)).multiply(z.modPow(n,nSPlusOne))).mod(nSPlusOne)).compareTo(
			        (b.multiply(c.modPow(e,nSPlusOne))).mod(nSPlusOne)		
			       )==0);
		} catch (java.lang.ArithmeticException f) {
			// The above may fail if the number was corrupted.
			return false;
		}
	}

	/**
	 * Verifies that the values used in this Zero Knowledge Proof corresponds
	 * to the given key.
	 * 
	 * @param origkey	A given key
	 * @return			The truth of the computation of <i>c<sub>i</sub></i> as
	 * 					being encrypted by {@code origkey}
	 */
	public boolean verifyKey(PaillierKey origkey) {
		if (this.nSPlusOne.equals(origkey.getNSPlusOne())
				&& this.n.equals(origkey.getN())) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Encodes this ZKP into a byte array.  All of the necessary values
	 * (including the public key values) needed
	 * to verify the veracity of this encryption are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #EncryptionZKP(byte[])
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArray() {
		// Encoding:
		// [ prev layer ]
		// [ size of nsplusone ]
		// [ nsplusone ]
		// [ size of n ]
		// [ n ]
		
		return ByteUtils.appendBigInt(toByteArrayNoKey(), nSPlusOne, n);
	}
	
	/**
	 * Encodes this ZKP into a byte array.  All of the necessary values (besides
	 * the public key values) needed
	 * to verify the veracity of this encryption are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #EncryptionZKP(byte[], PaillierKey)
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArrayNoKey() {
		// Encoding:
		// [ size of c ]
		// [ c ]
		// [ size of b ]
		// [ b ]
		// [ size of w ]
		// [ w ]
		// [ size of z ]
		// [ z ]
		
		byte[] p = c.toByteArray();
		byte[] r = new byte[p.length + 4];
		System.arraycopy(ByteUtils.intToByte(p.length), 0, r, 0, 4);
		System.arraycopy(p, 0, r, 4, p.length);
		
		return ByteUtils.appendBigInt(r, b, w, z);
	}
}
