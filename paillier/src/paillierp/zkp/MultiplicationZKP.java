/**
 * MultiplicationZKP.java
 */
package paillierp.zkp;

import java.math.BigInteger;
import paillierp.key.*;
import paillierp.ByteUtils;

/**
 * A non-interactive Zero Knowledge Proof that the multiplication of a
 * ciphertext is done.  This Zero Knowledge Proof will correctly
 * validate whether the message of the ciphertext <i>E</i>(<i>a</i>) was indeed
 * multiplied by a constant &alpha;.  This is done without revealing the value
 * &alpha; and without interaction.
 * <p>
 * The protocol is given on p. 40 in <i>Multiparty Computation from
 * Threshold Homomorphic Encryption</i> by Cramer, Damg&aring;rd, and
 * Nielsen.
 * 
 * @author Murat Kantarcioglu
 * @author Sean Hall
 * @author James Garrity
 */
public class MultiplicationZKP extends ZKP {
	
	/*
	 * 
	 * Fields
	 * 
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = -4809038851300738821L;

	/** The original encryption <i>E</i>(<i>a</i>). */
	private BigInteger ca;
	
	/** A random encryption of &alpha;. */
	private BigInteger c;
	
	/** A random encryption of <i>E</i>(<i>a&alpha</i>). */
	private BigInteger d;
	
	/** A random encryption of <i>E</i>(<i>xa</i>) for chosen <i>x</i>. */
	private BigInteger a;
	
	/** A random encryption of <i>x</i>. */
	private BigInteger b;
	
	/** <i>x+e&alpha;</i> mod <i>n</i>*/
	private BigInteger w;
	
	/** 
	 * <i>vC<sub>a</sub><sup>t</sup>&gamma;<sup>e</sup></i> 
	 * mod <i>n</i><sup>2</sup> 
	 */
	private BigInteger y;
	
	/** <i>us<sup>e</sup>g<sup>t</sup></i> mod <i>n</i><sup>2</sup> */
	private BigInteger z;
	
	/** The public key modulo. */
	private BigInteger n;
	
	/** The public key modulo to the <i>s</i>+1 power. */
	private BigInteger nSPlusOne;
	
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
	public MultiplicationZKP(byte[] b) {
		//TODO error if b.length = 0
		try{
			int offset = 0;
			
			int size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.ca = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.c = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.d = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.a = ByteUtils.getBigInt(b, offset, size);
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
			this.y = ByteUtils.getBigInt(b, offset, size);
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
	public MultiplicationZKP(byte[] b, BigInteger nSPlusOne, BigInteger n) {
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
	public MultiplicationZKP(byte[] b, PaillierThresholdKey pubkey) {
		this(b,pubkey.getNSPlusOne(), pubkey.getN());
	}
	
	/**
	 * Computes a random encryption of <i>&alpha;a</i> where <i>a</I> is the
	 * message encrypted in {@code ca}.  This additionally sets up a
	 * Zero Knowledge Proof that this multiplication was done, without revealing
	 * anything of &alpha;.
	 * 
	 * @param key       Public key <i>n</i> under which {@code ca} was encrypted 
	 * @param ca        The encryption <i>E</i>(<i>a</i>, <i>r</i>)
	 * @param alpha     The constant &alpha;
	 */
	public MultiplicationZKP(PaillierKey key, BigInteger ca, BigInteger alpha) {
		if(!key.inModNSPlusOneStar(ca)) {
			throw new IllegalArgumentException("ca must be relatively prime to n^2 and 0 <= ca < n^2");
		}
		BigInteger a=null;
		BigInteger c=null;
		BigInteger b=null;
		BigInteger d=null;
		BigInteger e=null;
		BigInteger x=null;
		BigInteger w=null;
		BigInteger t=null;
		BigInteger z=null;
		BigInteger y=null;
		BigInteger s=null;
		BigInteger u=null;
		BigInteger v=null;
		BigInteger gamma=null;
		BigInteger dummy=null;
		
		BigInteger nSquare = key.getNSPlusOne();
		
		//c (C_alpha in the paper) is basically the encryption of alpha 
		//s is the randomness required for encrypting alpha
		//s = key.getRandomModNStar();
		s = key.getRandomModNSPlusOneStar();
		
		//gamma is the randomness required for multiplication
		//gamma = key.getRandomModNStar();
		gamma = key.getRandomModNSPlusOneStar();
		
		// calculate s^n mod nSquare 	
		//calculate (1+n)^alpha*(s^n) mod n^2
		c=((key.getNPlusOne().modPow(alpha,nSquare)).multiply(
				s.modPow(key.getN(),nSquare))).mod(nSquare);	
		
		//x is a random element from Z_N
		x = key.getRandomModN();
		
		// we need to find an u in $Z^*_{N^2}$
		u = key.getRandomModNSPlusOneStar();
		
		// we need to find a v in $Z^*_{N^2}$
		v = key.getRandomModNSPlusOneStar();
		
		//a=ca^x.v^N mod N^2
		a=((ca.modPow(x,nSquare)).multiply(v.modPow(key.getN(),nSquare))).mod(nSquare);
		
		//b=(1+n)^x u^N mod N^2
		b=((key.getNPlusOne().modPow(x,nSquare)).multiply(
				u.modPow(key.getN(),nSquare))).mod(nSquare);
		
		//ca^alpha.gamma^n mod N^2
		d=((ca.modPow(alpha,nSquare)).multiply(
				gamma.modPow(key.getN(),nSquare))).mod(nSquare);
		
		// Calculate the Hash function to create random choice e
		e = hash(ca.toByteArray(), c.toByteArray(), d.toByteArray(), a.toByteArray(), b.toByteArray());
		
		//w=x+e*alpha mod N
		dummy=x.add(e.multiply(alpha));
		w=dummy.mod(key.getN());
		t=dummy.divide(key.getN());
		
		//$z=u.s^e.(1+n)^t$
		z=((u.multiply(s.modPow(e,nSquare))).multiply(key.getNPlusOne().modPow(t,nSquare))).mod(nSquare);
		
		//y=v.ca^t.gamma^e mod n^2
		y=((v.multiply(ca.modPow(t,nSquare))).multiply(gamma.modPow(e,nSquare))).mod(nSquare);
		
		this.nSPlusOne = key.getNSPlusOne();
		this.n = key.getN();
		this.ca=ca;
		this.c=c;
		this.d=d;
		this.a=a;
		this.b=b;
		this.w=w;
		this.y=y;
		this.z=z;
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * A random encryption of <i>a&alpha;</i>.
	 * 
	 * @return     <i>E</i>(<i>a&alpha;</i>, <i>r</i>) for some random <i>r</i>
	 */
	public BigInteger getValue() {
		return d;
	}
	
	/**
	 * Verifies if all of the above integers are indeed true, thereby showing 
	 * that this multiplication is exact.
	 * 
	 * @return     True if the computed value is indeed a random encryption
	 *             of a multiplication
	 */
	public boolean verify() {
		BigInteger e = hash(ca.toByteArray(), c.toByteArray(), d.toByteArray(), a.toByteArray(), b.toByteArray());
		
		try {
			if (((((n.add(BigInteger.ONE)).modPow(w,nSPlusOne)).multiply(z.modPow(n,nSPlusOne))).mod(nSPlusOne)).compareTo(
					(b.multiply(c.modPow(e,nSPlusOne))).mod(nSPlusOne)		
					)!=0) 
				return false;
			if ((((ca.modPow(w,nSPlusOne)).multiply(y.modPow(n,nSPlusOne))).mod(nSPlusOne)).compareTo(
					(a.multiply(d.modPow(e,nSPlusOne))).mod(nSPlusOne)		
				)!=0) 
				return false;
		} catch (java.lang.ArithmeticException f) {
			// The above may fail if the number was corrupted.
			return false;
		}
	  
		return true;
	}

	/**
	 * Verifies that the values used in this Zero Knowledge Proof corresponds
	 * to the given key.
	 * 
	 * @param origkey		
	 * @return			True iff the modulus of this ZKP is the same as the
	 * 					modulus of the provided key.
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
	 * to verify the veracity of this ciphertext multiplication are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #MultiplicationZKP(byte[])
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
	 * to verify the veracity of this ciphertext multiplication are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #MultiplicationZKP(byte[], PaillierThresholdKey)
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArrayNoKey() {
		// Encoding:
		// [ size of ca ]
		// [ ca ]
		// [ size of c ]
		// [ c ]
		// [ size of d ]
		// [ d ]
		// [ size of a ]
		// [ a ]
		// [ size of b ]
		// [ b ]
		// [ size of w ]
		// [ w ]
		// [ size of y ]
		// [ y ]
		// [ size of z ]
		// [ z ]
		
		byte[] p = ca.toByteArray();
		byte[] r = new byte[p.length + 4];
		System.arraycopy(ByteUtils.intToByte(p.length), 0, r, 0, 4);
		System.arraycopy(p, 0, r, 4, p.length);
		
		return ByteUtils.appendBigInt(r, c, d, a, b, w, y, z);
	}
}
