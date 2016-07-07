/**
 * ZKP.java
 */
package paillierp.zkp;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import paillierp.key.PaillierKey;

/**
 * An abstract class for non-interactive Zero Knowledge Proofs.  This class
 * gives the simple necessities for creating a Zero Knowledge Proof which uses
 * the hash of values as inputs.
 * 
 * @author Sean Hall
 */
public abstract class ZKP implements Serializable{

	/*
	 * 
	 * Fields
	 *
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = -3342470520881661778L;
	
	/**
	 * Instance of a hash function.
	 */
	protected MessageDigest hashFunction; 
	
	/*
	 * 
	 * Constructors
	 * 
	 */
	
	/**
	 * Default constructor.  Uses SHA-1 as the hash function.
	 */
	public ZKP() {
		this("SHA-1");
	}
	
	/**
	 * Creates a ZKP with the specified function as the hash function.
	 * @param hashFunctionName  Name of the hash function
	 */
	public ZKP(String hashFunctionName) {
		try {
			this.hashFunction = java.security.MessageDigest.getInstance(hashFunctionName);
		}
		catch(NoSuchAlgorithmException nsae) {
			System.out.println("No such algo: "+ nsae.toString());
		}
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Creates a hash of the given array of bytes
	 * 
	 * @param byteArrays     original array of bytes
	 * @return               hash of the concatenation of each element of
	 *                       byteArrays
	 */
	protected BigInteger hash(byte[]... byteArrays) {
		if(byteArrays.length == 0) throw new IllegalArgumentException("You must supply at least one array");
		for(int i = 0; i < byteArrays.length - 1; i++) {
			hashFunction.update(byteArrays[i]);
		}
		return new BigInteger(hashFunction.digest(byteArrays[byteArrays.length - 1]));
	}
	
	/**
	 * Verifies that the rehash of the particular variables is indeed
	 * the specified hash.
	 * 
	 * @return               Description of this proof
	 */
	public abstract boolean verify();
	
	public abstract byte[] toByteArray();
	
	public abstract byte[] toByteArrayNoKey();
	
	public abstract BigInteger getValue();
}
