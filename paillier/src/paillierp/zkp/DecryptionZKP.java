/**
 * DecryptionZKP.java
 * Provides a non-interactive Zero Knowledge Proof that a share has been decrypted
 */
package paillierp.zkp;

import java.math.BigInteger;
import paillierp.PartialDecryption;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.key.PaillierThresholdKey;
import paillierp.ByteUtils;


/**
 * A non-interactive Zero Knowledge Proof that some partial decryption was done.
 * (Note that this is only for the threshold version of the scheme.)
 * This is essentially a protocol for the equality of discrete logs, i.e. given
 * <i>u, u', v, v'</i>, prove that log<sub><i>u</i></sub>(<i>u'</i>) =
 * log<sub><i>v</i></sub>(<i>v'</i>).  This Zero Knowledge Proof will correctly
 * validate whether the ciphertext <i>c</i> was indeed raised to the
 * 2&Delta;<i>s<sub>i</sub></i> power by comparing it with the public verification
 * <i>v<sub>i</sub></i>.  This checks that
 * log<sub><i>c</i><sup>4</sup></sub>(<i>c<sub>i</sub></i><sup>2</sup>) = 
 * log<sub><i>v</i></sub>(<i>v<sub>i</sub></i>).  Recall that
 * <i>v<sub>i</sub></i> = <i>v</i><sup>&Delta;<i>s<sub>i</sub></i></sup>.
 * <p>
 * The protocol is given on pp. 16-17 in <i>Generalization of Paillier's
 * Public-Key System with Applications to
 * Electronic Voting</i> by Damg&aring;rd et al.
 * 
 * @author Murat Kantarcioglu
 * @author Sean Hall
 * @author James Garrity
 * @see paillierp.PaillierThreshold
 */
public class DecryptionZKP extends ZKP {

	/*
	 * 
	 * Fields
	 * 
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = -4912198730705411591L;

	/** The hash of the correctness. */
	protected BigInteger e;
	
	/** The value necessary to check the correctness of this decryption. */
	protected BigInteger z;
	
	/** The original ciphertext. */
	protected BigInteger c;
	
	/** The ciphtertext to the fourth power. */
	protected BigInteger c4;
	
	/**
	 * This share's decryption of <code>c</code>. That is,
	 * <code>ci</code> = <code>c</code><sup>2&Delta;<i>s<sub>i</sub></i></sup>.
	 */
	protected PartialDecryption ci;
	
	/** The share's decryption of <code>c</code>, but squared, for the protocol. */
	protected BigInteger ci2;
	
	/** The public key value.  Needed for verifying values.  */
	protected BigInteger nSPlusOne;
	
	/** The overall verification number. Needed for verifying values. */
	protected BigInteger v;
	
	/** The share's verification number. Needed for verifying values. */
	protected BigInteger vi;
	
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
	public DecryptionZKP(byte[] b) {
		//TODO error if b.length = 0
		try {
			int offset = 0;
			
			int id = ByteUtils.getInt(b, offset);
			offset += 4;
			
			int size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.e = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.z = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.c = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.ci = new PartialDecryption(ByteUtils.getBigInt(b, offset, size), id);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.nSPlusOne = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.v = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			size = ByteUtils.getInt(b, offset);
			offset += 4;
			this.vi = ByteUtils.getBigInt(b, offset, size);
			offset += size;
			
			this.ci2 = this.ci.getDecryptedValue().modPow(BigInteger.valueOf(2), this.nSPlusOne);
			this.c4 = c.modPow(BigInteger.valueOf(4), this.nSPlusOne);
		} catch(ArrayIndexOutOfBoundsException e) {
			throw new IllegalArgumentException("byte input corrupted or incomplete");
		}
	}
	
	/**
	 * Creates an instance of the Zero Knowledge Proof from a byte array
	 * (which does not have the key) and the values necessary for verification.
	 * 
	 * @param b			byte array of the necessary values for a ZKP
	 * @param nSPlusOne	the public key modulus <i>n<sup>s+1</sup></i>
	 * @param v			the public key verifier for partial decryptions
	 * @param vi		the public key verifier for partial decryptions from
	 * 					this particular server
	 * 
	 * @see #toByteArrayNoKey()
	 */
	public DecryptionZKP(byte[] b, BigInteger nSPlusOne, BigInteger v,
			BigInteger vi) {
		this(ByteUtils.appendBigInt(b, nSPlusOne, v, vi));
		// Even if b was created with toByteArray, it would simply
		// have nSPlusOne, v, and vi listed twice.
	}
	
	/**
	 * Creates an instance of the Zero Knowledge Proof from a byte array
	 * (which does <b>not</b> have the key) and a public key.
	 * 
	 * @param b			byte array of the necessary values for a ZKP
	 * @param pubkey	public Paillier key to provide further recurring
	 * 					values for a ZKP
	 * 
	 * @see #toByteArrayNoKey()
	 */
	public DecryptionZKP(byte[] b, PaillierThresholdKey pubkey) {
		this(b,pubkey.getNSPlusOne(), pubkey.getV(),
				pubkey.getVi()[ByteUtils.getInt(b, 0)]);
	}
	
	/**
	 * Creates an instance of the Zero Knoweledge Proof and partial decryption.
	 * By creating a hash of values including the partial decryption, this sets
	 * up the variables for a recomputation of the hash to verify the
	 * truth that <i>c<sub>i</sub></i> is indeed <i>c</i> partially decrypted.
	 * 
	 * @param deckey    Private key used to generate a partial decryption
	 * @param c         Ciphertext to be decrypted
	 */
	public DecryptionZKP(PaillierPrivateThresholdKey deckey, BigInteger c) {
		if(!deckey.inModNSPlusOne(c)) {
			throw new IllegalArgumentException("c must be: 0 <= c < n^(s+1)");
		}
		
		// Generate a random number of (s+2)k+t bits long, where t is a secondary security
		//   parameter (here, simply the size of the output of the hash function)
		BigInteger r = new BigInteger(3*deckey.getK()+this.hashFunction.getDigestLength(),deckey.getRnd());
		
		this.c = c;
		
		// This is the u in the protocol
		this.c4 = c.modPow(BigInteger.valueOf(4), deckey.getNSPlusOne());
				
		this.nSPlusOne = deckey.getNSPlusOne();
		this.v = deckey.getV();
		this.vi = deckey.getVi()[deckey.getID()-1];
		
		// a = c^4r mod n^(s+1)
		BigInteger a = c4.modPow(r, deckey.getNSPlusOne());
		
		// b = v^r mod n^(s+1)
		BigInteger b = deckey.getV().modPow(r, deckey.getNSPlusOne());
		
		// ci = c^(2*Delta*si)
		this.ci = new PartialDecryption(deckey, c);
		//this.ci = c.modPow(deckey.getSi().multiply(BigInteger.valueOf(2).multiply(deckey.getDelta())), deckey.getNSquare());
		
		// ci^2; the ~u in the protocol
		this.ci2 = this.ci.getDecryptedValue().modPow(BigInteger.valueOf(2), deckey.getNSPlusOne());
		
		// Hash the value H(a,b,c,ci)
		e = this.hash(a.toByteArray(),b.toByteArray(),c4.toByteArray(),ci2.toByteArray());
		
		// z = r + e*si*delta
		z = r.add(deckey.getSi().multiply(e).multiply(deckey.getDelta()));
	}

	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Evaluates the truth of this partial decryption.  By recomputing the hash,
	 * it checks to see that indeed <i>c<sub>i</sub></i> was computed correctly.
	 * 
	 * @return     The truth of the computation of <i>c<sub>i</sub></i>
	 */
	public boolean verify() {
		
		try {
			// tries to compute the original a = c^4z * ci^(2*-e)
			BigInteger a = c4.modPow(z, nSPlusOne).multiply(ci2.modPow(e.negate(), nSPlusOne)).mod(nSPlusOne);
			
			// tries to compute the original b = v^z * vi^(-e)
			BigInteger b = v.modPow(z, nSPlusOne).multiply(vi.modPow(e.negate(), nSPlusOne)).mod(nSPlusOne);
	
			// tries to rehash the value H(a, b, c^4, ci)
			BigInteger e = this.hash(a.toByteArray(),b.toByteArray(),c4.toByteArray(),ci2.toByteArray());
	
			// see if the original hash is equal to the guessed hash
			if (e.compareTo(this.e) == 0) {
				return true;
			} else {
				return false;
			}
		} catch (java.lang.ArithmeticException e) {
			// The above may fail if the number was corrupted.
			return false;
		}
	}
	
	/**
	 * Evaluates the truth of this partial decryption as a partial decryption of
	 * {@code origc}.  By recomputing the hash,
	 * it checks to see that indeed <i>c<sub>i</sub></i> was computed correctly
	 * from {@code origc}.
	 * 
	 * @param origc	Original Ciphertext.
	 * @return     The truth of the computation of <i>c<sub>i</sub></i> as
	 *             coming from {@code origc}.
	 */
	public boolean verify(BigInteger origc) {
		if (this.c.compareTo(origc) == 0) {
			return verify();
		} else {
			return false;
		}
	}
	
	/**
	 * Verifies that the values used in this Zero Knowledge Proof corresponds
	 * to the given key.
	 * 
	 * @param origkey	Original key
	 * @return			The truth of the computation of <i>c<sub>i</sub></i> as
	 * 					being encrypted by {@code origkey}
	 */
	public boolean verifyKey(PaillierThresholdKey origkey) {
		if (this.nSPlusOne.equals(origkey.getNSPlusOne())
				&& this.v.equals(origkey.getV())
				&& this.vi.equals(origkey.getVi()[ci.getID()-1])) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Returns the original ciphertext.
	 * 
	 * @return     The ciphertext of which this is a partial decryption
	 */
	public BigInteger getC() {
		return c;
	}
	
	/**
	 * Returns the ID of the key used to make this partial decryption.
	 * 
	 * @return     The ID of the decryption server generating this partial
	 *             decryption
	 */
	public int getID() {
		return ci.getID();
	}

	/**
	 * The partial decryption intended to be delivered.
	 * 
	 * @return     A partial decryption <i>c<sub>i</sub></i>
	 * @see paillierp.PaillierThreshold#decrypt(BigInteger)
	 */
	public BigInteger getValue() {
		return ci.getDecryptedValue();
	}
	
	public PartialDecryption getPartialDecryption() {
		return ci;
	}
	
	/**
	 * Encodes this ZKP into a byte array.  All of the necessary values
	 * (including the public key values) needed
	 * to verify the veracity of this partial decryption are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #DecryptionZKP(byte[])
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArray() {
		// The encoding would be
		// [ previous layer ]
		// [ length of nSPlusOne ]
		// [ nSPlusOne ]
		// [ length of v ]
		// [ v ]
		// [ length of vi ]
		// [ vi ]
		return ByteUtils.appendBigInt(toByteArrayNoKey(), this.nSPlusOne,
				this.v, this.vi);
	}
	
	/**
	 * Encodes this ZKP into a byte array.  All of the necessary values (besides
	 * the public key values) needed
	 * to verify the veracity of this partial decryption are encoded.
	 * Before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			a byte array containing the most necessary values
	 * 					of this ZKP.  A byte array of size 0 is returned
	 * 					if the byte array would be too large.
	 * 
	 * @see #DecryptionZKP(byte[], PaillierThresholdKey)
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArrayNoKey() {
		// The encoding would be:
		// [ id ]
		// [ length of e ]
		// [ e ]
		// [ length of z ]
		// [ z ]
		// [ length of c ]
		// [ c ]
		// [ length of ci ]
		// [ ci ]
		
		byte[] r = ByteUtils.intToByte(this.ci.getID());
		
		r = ByteUtils.appendBigInt(r, e, z, c, ci.getDecryptedValue());
		
		return r;
	}
}
