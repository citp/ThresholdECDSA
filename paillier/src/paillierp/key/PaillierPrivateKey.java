/**
 * PaillierPrivateKey.java
 */
package paillierp.key;

import java.math.BigInteger;
import java.security.SecureRandom;
import paillierp.ByteUtils;

/** 
 * A simple private key for the generalized Paillier cryptosystem
 * <i>CS</i><sub>1</sub>.
 * <p>
 * The private key for the generalized Paillier cryptosystem
 * <i>CS<sub>s</sub></i> constructed in Damg&aring;rd et al. requires the public
 * key values of <i>n</i> and <i>g</i> (as provided for in {@link PaillierKey}),
 * and the secret value <i>d</i> as defined as follows:
 * <ul>
 *   <li><i>d</i> is an element such that
 *       <i>d</i> mod <i>n</i> &isin; <i>Z</i><sup>*</sup><sub><i>n</i></sub>
 *       and <i>d</i> = 0 mod &lambda; where
 *       &lambda;=lcm(<i>p</i>-1,<i>q</i>-1).
 * </ul>
 * 
 * 
 * @author James Garrity
 * @author Sean Hall
 * @version 1.0 03/25/10
 * @see PaillierKey
 */
public class PaillierPrivateKey extends PaillierKey {

	/*
	 * 
	 * Fields
	 * 
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = 5852433647485331139L;

	/**
	 * Secret key;
	 * <i>d</i> mod <i>n</i>&isin;<i>Z</i><sup>*</sup><sub><i>n</i></sub> and
	 * <i>d</i> = 0 mod &lambda;, where &lambda; is least common
	 * multiple of <i>p</i>-1 and <i>q</i>-1. */
	protected BigInteger d = null;
	
	/**
	 * The inverse of <i>d</i> mod <i>n<sup>s</sup></i>. Used in the final
	 * step of decryption.
	 */
	protected BigInteger dInvs = null;
	
	/*
	 * 
	 * Constructors
	 * 
	 */
	
	/** 
	 * Creates a new private key when given the modulus <i>n</i> and
	 * the secret value <i>d</i>.  This constructor will use the
	 * <code>seed</code> to create the public key with a
	 * {@link SecureRandom} random number generator.
	 * 
	 * @param n			a RSA modulus.  That is, the product of two
	 * 					different odd primes <i>p, q</i>.
	 * @param d			an integer that should be a multiple of the least
	 * 					common multiple of <i>p</i>-1 and <i>q</i>-1, and
	 * 					relatively prime to <code>n</code>
	 * @param seed		a long integer needed to start a random
	 * 					number generator
	 */
	public PaillierPrivateKey(BigInteger n, BigInteger d, long seed){
		super(n, seed);
		//checks to see that d mod n is relatively prime to n
		if (!(inModNStar(d.mod(n))))
			throw new IllegalArgumentException("d must be relatively prime to n");
		this.d = d;
		this.dInvs = this.d.modInverse(ns);
	}
	
	/**
	 * Creates a new private key when given the primes <i>p</i> and <i>q</i>
	 * and the secret value <i>d</i>.  This constructor will use the
	 * <code>seed</code> to create the public key with a
	 * {@link SecureRandom} random number generator.
	 * 
	 * @param p			one allowable prime for our modulus
	 * @param q			another prime for our modulus, different from 
	 * @param d			an integer that should be a multiple of the least
	 * 					common multiple of <code>p-1</code> and 
	 * 					<code>q-1</code>, and relatively prime to
	 * 					<code>p*q</code>
	 * @param seed		a long integer needed to start a random
	 * 					number generator
	 */
	public PaillierPrivateKey(BigInteger p, BigInteger q, BigInteger d, long seed) {
		super(p,q,seed);
		
		//!!!!Additional checks on d now that we know p and q!!!!
		
		//checks to see that d mod n is relatively prime to n
		if (!(inModNStar(d.mod(n))))
			throw new IllegalArgumentException("d must be relatively prime to n");
		
		// phi(n) = (p-1)*(q-1)
		BigInteger phin = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		// Now we can calculate the Carmichael's function for n i.e., lcm(p-1,q-1)
		// Note that phi(n)=gcd(p-1,q-1)*lcm(p-1,q-1)
		// lambda = lcm(p-1,q-1) = phi(n)/gcd(p-1,q-1)
		BigInteger lambda = phin.divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
		
		//checks to see that d = 0 mod lambda
		if (!(d.mod(lambda).compareTo(BigInteger.ZERO)==0))
			throw new IllegalArgumentException("d must be a multiple of lcm(p-1,q-1)");
		
		this.d = d;
		this.dInvs = this.d.modInverse(ns);
	}
	
	/**
	 * Creates a new private key using a byte encoding of a key.
	 * 
	 * @param b			Byte array of the necessary values of this private key
	 * @param seed		a long integer needed to start a random number generator
	 * 
	 * @see #toByteArray()
	 */
	public PaillierPrivateKey(byte[] b, long seed) {
		super(ByteUtils.getLowerLayer(b), seed);
		int offset = ByteUtils.getInt(b, b.length-4); // start of this layer's data
		
		this.d = ByteUtils.getBigInt(b, offset+4, ByteUtils.getInt(b, offset));
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Describes if this key can be used to encrypt
	 * 
	 * @return		'true' if it can encrypt.
	 */
	public boolean canEncrypt() {
		return true;
	}
	
	/**
	 * Accesses the secret integer <i>d</i> chosen at the creation of this
	 * secret key.  In the generalized Paillier cryptosystem, ciphertext
	 * <i>E</i>(<i>i</i>,<i>r</i>) raised to the <i>d</i> power will result
	 * in (1+<i>n</i>)<sup><i>jid</i> mod <i>n<sup>s</sup></i></sup>.  Applying
	 * a method, one can easily find <i>jid</i> and <i>jd</i>, allowing one to
	 * find <i>i</i> mod <i>n<sup>s</sup></i>.  Note that in our simplified
	 * version, both <i>s</i> and <i>j</i> are 1.
	 * 
	 * @return		the secret integer that allows decryption
	 */
	public BigInteger getD() {
		return d;
	}
	
	/**
	 * Access the precomputed inverse of <code>d</code> in
	 * <i>Z</i><sup>*</sup><sub><i>n</i><sup><i>s</i>+1</sup></sub>.  This
	 * allows one to decrypt a little more expediently.
	 * @return		the inverse of <code>d</code> in mod
	 * 				<code>n</code><sup>2</sup>
	 * @see			#getD()
	 */
	public BigInteger getDInvs() {
		return dInvs;
	}
	
	/**
	 * Returns a BigInt array corresponding to this Paillier pubilc key.
	 */
	public BigInteger[] toIntArray() {
		BigInteger[] r = new BigInteger[2];
		r[0] = n;
		r[1] = d;
		return r;
	}
	
	/**
	 * Encodes this key into a byte array.  As this is a public key,
	 * the public modulo {@code n}, {@code d} will be encoded in that order.
	 * Further, before {@code d} is the 4-byte equivalent to the size of
	 * the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this key.  A byte array of size 0 is returned
	 * 					if the key would be too large.
	 * 
	 * @see #PaillierPrivateKey(byte[], long)
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArray() {
		// The encoding would be:
		// [ prev. layer ]
		// [ size of d ]
		// [ d ]
		// [ length of previous layer ]
		
		byte[] p = super.toByteArray(); // previous layer
		
		byte[] r = ByteUtils.appendBigInt(p, this.d);
		r = ByteUtils.appendInt(r, p.length);
		
		return r;
		
//		byte[] d = this.d.toByteArray();
//
//		byte[] r; // the return array
//		
//		if ((long)p.length+(long)d.length+(long)(4+4) > Integer.MAX_VALUE) {
//			r = new byte[0];
//		} else {
//			r = new byte[p.length+d.length+4+4];
//			//throw error if |n| + |d| + 8 > MAX_INT
//			System.arraycopy(p, 0,
//					r, 0, p.length);
//			System.arraycopy(intToByte(d.length), 0,
//					r, p.length, 4);
//			System.arraycopy(d, 0,
//					r, 4+p.length, d.length);
//			System.arraycopy(intToByte(p.length), 0,
//					r, p.length+4+d.length, 4);
//		}
//		
//		return r;
	}
}
