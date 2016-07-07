/**
 * PartialDecryption.java
 */
package paillierp;

import java.io.Serializable;
import java.math.BigInteger;

import paillierp.key.PaillierPrivateThresholdKey;

/**
 * A partial decryption in the Threshold Paillier encryption scheme with
 * necessary data to proceed with the full decryption.  To produce the full
 * decryption of any ciphertext, at least <i>w</i> decryption servers must
 * provide their partial decryptions.  Furthermore, the source ID of each
 * partial decryption is essential in combining the shares to produce a
 * full and complete decryption of the original ciphertext.  For this reason,
 * a special datatype has been produced to hold only the partial decryption
 * and the source ID.
 * 
 * @author James Garrity
 */
public class PartialDecryption implements Serializable {
	
	/*
	 * 
	 * Fields
	 * 
	 */

	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = -6668831686028175205L;
	
	/** The partial decryption */
	private BigInteger decryption;
	
	/** The ID number of the decryption server who decrypted this. */
	private int id;
	
	/*
	 * 
	 * Constructors
	 * 
	 */
	
	/**
	 * Links the partial decryption {@code decryption} as coming from
	 * decryption server {@code id}.
	 * 
	 * @param decryption     a partial decryption
	 * @param id             the id of the secret key who composed this
	 *                       partial decryption
	 */
	public PartialDecryption(BigInteger decryption, int id) {
		this.decryption = decryption;
		this.id = id;
	}
	
	/**
	 * Translates a byte array, of which the first four bytes contain the id
	 * and the last number of bytes contain the two's complement binary
	 * representation of a BigInteger.
	 * 
	 * @param b
	 */
	public PartialDecryption(byte[] b) {
		byte[] dec = new byte[b.length-4];
		System.arraycopy(b, 4, dec, 0, dec.length);
		this.decryption = new BigInteger(dec);
		this.id = b[0]<<24 + b[1]<<16 + b[2]<<8 + b[3];
	}
	
	/**
	 * Computes the partial decryption of {@code ciphertext} using the
	 * private key {@code key}.  This is essentially the value
	 * {@code ciphertext}<sup>2&Delta;<i>s<sub>i</sub></i></sup>.
	 * 
	 * @param key            private key of decryption server <i>i</i>
	 * @param ciphertext     original ciphertext
	 */
	public PartialDecryption(PaillierPrivateThresholdKey key, BigInteger ciphertext) {
		//Check whether everything is set for doing decryption
		if(!key.inModNSPlusOne(ciphertext)) throw new IllegalArgumentException("c must be less than n^2");

		this.decryption = ciphertext.modPow(key.getSi().multiply(BigInteger.valueOf(2).multiply(key.getDelta())), key.getNSPlusOne());
		this.id = key.getID();
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Returns the partial decryption string
	 * 
	 * @return          the value <i>c<sub>i</sub></i>
	 */
	public BigInteger getDecryptedValue() {
		return this.decryption;
	}
	
	/**
	 * Returns the ID of the secret key which produced this partial decryption
	 * 
	 * @return          the secret key ID used
	 */
	public int getID() {
		return this.id;
	}
	
	/**
	 * Returns a byte array where the first four bytes signify the ID and the
	 * remaining signify the partial decryption.
	 * 
	 * @return			byte array of the ID concatenated to byte array of
	 * 					the partial decryption.
	 */
	public byte[] toByteArray() {
		// The encoding would be
		// [ id ]
		// [ decryption ]
		
		byte[] dec = this.decryption.toByteArray();
		byte[] b = new byte[4+dec.length];
        for (int i = 0; i < 4; i++) {
            int offset = (3 - i) * 8;
            b[i] = (byte) ((id >>> offset) & 0xFF);
        }
        System.arraycopy(dec, 0, b, 4, dec.length);
        return b;
	}
}
