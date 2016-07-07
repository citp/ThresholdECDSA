/**
 * AbstractPaillier.java
 */
package paillierp;

import java.math.BigInteger;

import paillierp.key.*;
import paillierp.zkp.EncryptionZKP;
import paillierp.zkp.MultiplicationZKP;

/**
 * An abstract class of the simple Paillier cryptosystem.  This class
 * is intended for use in both the {@link Paillier} and
 * {@link PaillierThreshold} implementations of the generalized Paillier
 * cryptosystem by Damg&aring;rd.
 * <p>
 * This includes methods and fields common to both implementations, especially
 * encryption and operations on ciphertexts; more specifically, the following
 * operations are provided in this abstract class:
 * <ul>
 *    <li>encrypting messages,
 *    <li>random encryptions of 0 and 1,
 *    <li>randomizing a ciphertext,
 *    <li>addition of two ciphertexts,
 *    <li>multiplication of a ciphertext by a constant.
 * </ul>
 * Any operations needing the decryption key is left to the specific
 * cryptosystem and is not included in this class.
 * <p>
 * Note that every ciphertext and plaintext is a {@link BigInteger}.
 * 
 * @author Sean Hall
 * @author James Garrity
 * @see Paillier
 * @see PaillierThreshold
 */
public abstract class AbstractPaillier {
	
	/*
	 * NOTE TO ANY CONTRIBUTORS TO THIS CODE:
	 * A little history of this project:  this code was originally designed for
	 * the condition that l and w were fixed at 2.  A huge effort was made to
	 * change this for any arbitrary l and w, but with s fixed to one.  This
	 * means that all of the code was originally programmed for
	 *  - n^s = n
	 *  - n^(s+1) = n^2
	 * At the very end of this project, a small effort was made to change any
	 * nSquare's to nSPlusOne and many n's to ns, but this was originally not
	 * so.  There are still some residues for checking messages to be in mod
	 * n and not n^s.  Some parameters are still called nSquared when they
	 * should be nSPlusOne.  Be through in your updating of this code to allow
	 * s to be arbitrary.
	 * 
	 *   Thanks,
	 *   James Garrity
	 *   2010 April 27
	 * 
	 */
	
	/*
	 * 
	 * Fields
	 * 
	 */
	
	//Values are made protected for inheritance reasons
	
	/** Public Key allowing encryption. */
	protected PaillierKey key = null;
	
	/** Boolean signifying that the variables for encryption are in place. */
	protected boolean encryptMode=false;
	
	/** Boolean signifying that the variables for decryption are in place. */
	protected boolean decryptMode=false;
	
	/**
	 * String for error messages indicating that <code>encryptMode</code>
	 * is not set.
	 */
	protected String notReadyForEncryption =
		"You must first call setEncrypt or setDecryptEncrypt before calling this method";
	
	/**
	 * String for error messages indicating that <code>decryptMode</code>
	 * is not set.
	 */
	protected String notReadyForDecryption =
		"You must first call setDecrypt or setDecryptEncrypt before calling this method";

	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Returns the simple public key already in use in this instance of the
	 * cryptosystem.  This includes the two
	 * values <i>n</i> and <i>g</i> needed for encryption.  Returns <code>
	 * null</code> if no key has yet to be specified.
	 * 
	 * @return			the Paillier public key in use; <code>null</code>
	 * 					if the key is not initialized.
	 */
	public PaillierKey getPublicKey()
	{
		if (key==null) {
			return null;
		}
		
		//Calls the key's getPublicKey method in case this class
		// was given a private key for the public key.
		return key.getPublicKey(); 
	}
	
	/**
	 * Produces the random encryption of {@code m}.
	 *  
	 * @param m 		plaintext to be encrypted; must be less than
	 * 					<code>n</code><sup><i>s</i></sup>
	 * @return 			the encryption <i>E</i>(<code>m</code>,<i>r</i>)
	 * 					with a random <i>r</i>
	 */
	public BigInteger encrypt(BigInteger m)
	{  	
		return encrypt(m, key.getRandomModNStar(), key);
	}

	/**
	 * Produces the encryption <i>E</i>({@code m}, {@code r}) using the
	 * message {@code m} and the randomization {@code r}
	 * in the Paillier cryptosystem.
	 *  
	 * @param m 		plaintext to be encrypted; must be less than
	 * 					<code>n</code><sup><i>s</i></sup>
	 * @param r			randomizer integer for the encryption; must be 
	 * 					relatively prime to <code>n</code> and less than
	 * 					<code>n</code>
	 * @return 			the encryption <i>E</i>(<code>m</code>,<code>r</code>)
	 */
	public BigInteger encrypt(BigInteger m, BigInteger r)
	{
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);
		
		return encrypt(m, r, key);
	}
	
	/**
	 * Produces a random encryption of {@code m}
	 * 
	 * @param m         Message to be encoded; {@code m<ns}
	 * @param key       Public Key doing the encoding
	 * @return          The encryption <i>E</i>(<code>m</code>, <i>r</i>) using
	 *                  the public key {@code key} with random <i>r</i>
	 */
	public static BigInteger encrypt(BigInteger m, PaillierKey key) {
		return encrypt(m, key.getRandomModNStar(), key.getN(), key.getNS(), key.getNSPlusOne());
	}
	
	/**
	 * Produces the encryption <i>E</i>(<code>m, r</code>).
	 * 
	 * @param m         Message to be encoded; {@code m<ns}
	 * @param r         Random number in <i>Z</i><sup>*</sup><sub>{@code n}</sub>
	 * @param key       Public Key doing the encoding
	 * @return          The encryption <i>E</i>(<code>m, r</code>) using
	 *                  the public key {@code key}
	 */
	public static BigInteger encrypt(BigInteger m, BigInteger r, PaillierKey key) {
		return encrypt(m, r, key.getN(), key.getNS(), key.getNSPlusOne());
	}
	
	/**
	 * Produces the encryption <i>E</i>(<code>m, r</code>).
	 * 
	 * @param m         Message to be encoded; {@code m<ns}
	 * @param r         Random number in <i>Z</i><sup>*</sup><sub>{@code n}</sub>
	 * @param n         RSA modulus
	 * @param ns        The value {@code n}<sup><i>s</i></sup>
	 * @param nSPlusOne The value {@code n}<sup><i>s</i>+1</sup>
	 * @return          The encryption <i>E</i>(<code>m, r</code>) using
	 *                  the public key {@code n}
	 */
	public static BigInteger encrypt(BigInteger m, BigInteger r, BigInteger n, BigInteger ns, BigInteger nSPlusOne) {
		if(!(PaillierKey.inModN(m,ns))) {
			throw new IllegalArgumentException("m must be less than n^s");
		}

		if(!(PaillierKey.inModNStar(r,n))) {
			throw new IllegalArgumentException("r must be relatively prime to n and 0 <= r < n");
		}
		
		return (n.add(BigInteger.ONE).modPow(m, nSPlusOne).multiply(r.modPow(ns, nSPlusOne)).mod(nSPlusOne));
	}
	
	/**
	 * Produces a Zero Knowledge Proof of the encryption {@code m}
	 * 
	 * @param m         A message to be encrypted (must be less than {@code n}
	 * @return          A non-interactive Zero Knowledge Proof that we in fact
	 *                  encrypted {@code m}
	 */
	public EncryptionZKP encryptProof(BigInteger m) {
		return new EncryptionZKP(this.key, m);
	}
	
	/**
	 * A random encryption of 0.
	 *  
	 * @return 			the encrypted value <i>E</i>(0,<i>r</i>) with
	 * 					random <i>r</i>
	 */
	public BigInteger encryptzero()
	{
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);

		return encrypt(BigInteger.ZERO, key);
	}

	/**
	 * A random encryption of 1.
	 *  
	 * @return 			the encrypted value <i>E</i>(1,<i>r</i>) with
	 * 					random <i>r</i>
	 */
	public BigInteger encryptone()
	{
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);

		return encrypt(BigInteger.ONE, key);
	}

	/**
	 * Calculates <i>E</i>(<i>m</i><sub>1</sub>+<i>m</i><sub>2</sub>) given
	 * <i>E</i>(<i>m</i><sub>1</sub>) and <i>E</i>(<i>m</i><sub>2</sub>).
	 * 
	 * @param c1	the encryption <i>E</i>(<i>m</i><sub>1</sub>)
	 * @param c2 	the encryption <i>E</i>(<i>m</i><sub>2</sub>)
	 * @return		the encryption <i>E</i>(<i>m</i><sub>1</sub>+<i>m</i><sub>2</sub>)
	 */
	public BigInteger add(BigInteger c1, BigInteger c2)
	{
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);
		if(!(key.inModNSPlusOne(c1))) throw new IllegalArgumentException("c1 must be less than n^(s+1)");
		if(!(key.inModNSPlusOne(c2))) throw new IllegalArgumentException("c2 must be less than n^(s+1)");
		return (c1.multiply(c2)).mod(key.getNSPlusOne());	
	}

	/**
	 * Calculates <i>E</i>(<i>m</i><sub>1</sub>+<i>m</i><sub>2</sub>) given
	 * <i>E</i>(<i>m</i><sub>1</sub>) and <i>E</i>(<i>m</i><sub>2</sub>), for
	 * a given cryptosystem <i>CS<sub>s</sub></i> with public key <i>n</i>
	 * 
	 * @param c1		the encryption <i>E</i>(<i>m</i><sub>1</sub>) under the
	 * 					public key <i>n</i>
	 * @param c2 		the encryption <i>E</i>(<i>m</i><sub>2</sub>) under the
	 * 					public key <i>n</i>
	 * @param nsplus1	<i>n</i> to the (<i>s</i>+1)th power
	 * @return			the encryption
	 * 					<i>E</i>(<i>m</i><sub>1</sub>+<i>m</i><sub>2</sub>)
	 * 					under the supposed public key <i>n</i> in cryptosystem
	 * 					<i>CS<sub>s</sub></i>.
	 */
	public static BigInteger add(BigInteger c1, BigInteger c2, BigInteger nsplus1)
	{	
		if(c1.abs().compareTo(nsplus1) >= 0) throw new IllegalArgumentException("c1 must be less than n^(s+1)");
		if(c2.abs().compareTo(nsplus1) >= 0) throw new IllegalArgumentException("c2 must be less than n^(s+1)");
		return (c1.multiply(c2)).mod(nsplus1);
	}

	/**
	 * Calculates <i>E</i>(<code>cons*</code><i>m</i>) given <i>E</i>(<i>m</i>)
	 * and the constant <code>cons</code>, under our current public key.
	 * 
	 * @param c1        the encryption <i>E</i>(<i>m</i>)
	 * @param cons      the integer multiplicand
	 * @return          the encryption <i>E</i>(<code>cons*</code><i>m</i>)
	 */
	public BigInteger multiply(BigInteger c1, long cons)
	{
		// In order to multiply, we need to raise the
		// cipher text cons power mod nSquare
		return multiply(c1,BigInteger.valueOf(cons));
	}

	/**
	 * Calculates <i>E</i>(<code>cons*</code><i>m</i>) given <i>E</i>(<i>m</i>)
	 * and the constant <code>cons</code>, under our current public key.
	 * 
	 * @param c1        the encryption <i>E</i>(<i>m</i>)
	 * @param cons      the integer multiplicand
	 * @return          the encryption <i>E</i>(<code>cons*</code><i>m</i>)
	 */
	public BigInteger multiply(BigInteger c1, BigInteger cons)
	{	
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);
		if(!(key.inModNSPlusOne(c1))) throw new IllegalArgumentException("c1 must be less than n^2");
		return c1.modPow(cons,key.getNSPlusOne());
	}

	/**
	 * Calculates <i>E</i>(<code>cons*</code><i>m</i>) given <i>E</i>(<i>m</i>)
	 * and the constant <code>cons</code>, under our current public key.  This
	 * method then returns a non-interactive Zero Knowledge Proof that
	 * the resulting encryption (i.e. <i>E</i>(<code>cons*</code><i>m</i>)) is
	 * indeed the encryption of the multiplication of <i>m</i> by {@code cons}.
	 * 
	 * @param c1        the encryption <i>E</i>(<i>m</i>)
	 * @param cons      the integer multiplicand
	 * @return          a ZKP of the encryption
	 *                  <i>E</i>(<code>cons*</code><i>m</i>)
	 */
	public MultiplicationZKP multiplyProof(BigInteger c1, BigInteger cons)
	{
		return new MultiplicationZKP(this.key, c1, cons);
	}
	
	/**
	 * Calculates <i>E</i>(<code>cons*</code><i>m</i>) given <i>E</i>(<i>m</i>)
	 * and the constant <code>cons</code>, under the public key <i>n</i> for
	 * crypto system <i>CS<sub>s</sub></i>.
	 * 
	 * @param c         the encryption <i>E</i>(<i>m</i>) under the
	 *                  public key <i>n</i>
	 * @param cons      the integer multiplicand
	 * @param nSquare   <i>n</i> to the (<i>s</i>+1)th power
	 * @return          the encryption <i>E</i>(<code>cons*</code><i>m</i>)
	 *                  under the supposed public key <i>n</i> in cryptosystem
	 *                  <i>CS<sub>s</sub></i>
	 */
	public static BigInteger multiply(BigInteger c, BigInteger cons, BigInteger nSquare)
	{
		if(c.abs().compareTo(nSquare) >= 0) throw new IllegalArgumentException("c1 must be less than n^2");
		return c.modPow(cons,nSquare);
	}
	
	/**
	 * Randomizes a given encryption by the given variable.  Given
	 * <i>E</i>(<i>m</i>,<i>r'</i>),
	 * it returns <i>E</i>(<i>m</i>,<i>r'</i>*<code>r</code>).
	 * 
	 * @param c		the encryption <i>E</i>(<i>m</i>,<i>r'</i>)
	 * @param r		randomizer variable; must be relatively prime to
	 * 				<i>n</i> and less than <i>n</i>
	 * @return		the encryption <i>E</i>(<i>m</i>,<i>r'</i>*<code>r</code>)
	 */
	public BigInteger randomize(BigInteger c, BigInteger r)
	{
		if(encryptMode==false) throw new IllegalStateException(this.notReadyForEncryption);
		if(!(key.inModNSPlusOne(c))) throw new IllegalArgumentException("c must be less than n^2");
		if(!(key.inModNStar(r))) throw new IllegalArgumentException("r must be relatively prime to n and 0<=r<n");
		return (c.multiply(r.modPow(key.getN(),key.getNSPlusOne()))).mod(key.getNSPlusOne());
	}

	/**
	 * Randomizes a given encryption by the given variable.  Given
	 * <i>E</i>(<i>m</i>,<i>r</i>),
	 * it returns <i>E</i>(<i>m</i>,<i>r'</i>) for random <i>r'</i>.
	 * 
	 * @param c		the encryption <i>E</i>(<i>m</i>,<i>r</i>)
	 * @return		the encryption <i>E</i>(<i>m</i>,<i>r'</i>) for a new
	 * 				random <i>r'</i>
	 * 
	 */
	public BigInteger randomize(BigInteger c)
	{
		return this.randomize(c, key.getRandomModNStar());
	}
}
