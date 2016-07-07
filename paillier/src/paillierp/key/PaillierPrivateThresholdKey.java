/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */package paillierp.key;

import java.math.BigInteger;

import paillierp.ByteUtils;

/**
 * A private key for the threshold Paillier scheme <i>CS</i><sub>1</sub>.  This
 * key is used to partially decrypt a ciphertext. At least
 * <i>{@linkplain PaillierThresholdKey#w}</i> cooperating decryption servers 
 * are needed in this scheme to produce a full decryption.  The public
 * information provided for in 
 * <p>
 * The private key in this threshold scheme requires the following information
 * to produce a partial decryption:
 * <ul>
 *   <li>The public values <i>&Delta;</i> and <i>n</i> provided for in
 *       {@link PaillierThresholdKey}
 *   <li><i>i</i> is the decryption server ID for this particular secret key
 *   <li><i>s<sub>i</sub></i>, which is the secret share particular to this
 *       server.  This value is no other than <i>f</i>(<i>i</i>) for the
 *       (<i>w</i>-1)-degree polynomial <i>f</i> created by the key
 *       distributor.
 * </ul>
 * 
 * @author James Garrity
 * @author Sean Hall
 * @version 0.9 03/25/10
 * @see PaillierKey
 * @see paillierp.key.KeyGen
 */
public class PaillierPrivateThresholdKey extends PaillierThresholdKey {
	
	/*
	 * 
	 * Fields
	 * 
	 */
	
	/**
	 * This Serial ID
	 */
	private static final long serialVersionUID = 5024312630277081335L;

	/**
	 * The secret share. This is unique among the <i>L</i> decryption
	 * servers.
	 */
	protected BigInteger si = null;
	
	/**
	 * The server's id in the range of [1, <code>l</code>].  This identifies
	 * which verification key <code>vi[id]</code> to use.
	 */
	protected int id;
	
	/*
	 * 
	 * Constructors
	 * 
	 */
	
	/**
	 * Creates a new private key for the generalized Paillier threshold scheme
	 * from the given modulus <code>n</code>, for use on <code>l</code>
	 * decryption servers, <code>w</code> of which are needed to decrypt
	 * any message encrypted by using this public key.  The values
	 * <code>v</code> and <code>vi</code> correspond to the public
	 * values <i>v</i> and
	 * <i>v<sub>i</sub></i>=<i>v</i><sup><i>l</i>!<i>s<sub>i</sub></i></sup>
	 * needed to verify the zero knowledge proofs.  {@code si} is the secret share
	 * for this decryption key, and {@code i} is the ID.
	 * 
	 * @param n        a safe prime product of <i>p</i> and <i>q</i> where
	 *                 <i>p'</i>=(<i>p</i>-1)/2 and <i>a'</i>=(<i>a</i>-1)/2
	 *                 are also both primes
	 * @param l        number of decryption servers
	 * @param w        threshold of servers needed to successfully decrypt any
	 *                 ciphertext created by this public key.  Note that
	 *                 <code>w</code>&le;<code>l</code>/2.
	 * @param v        a generator of a cyclic group of squares in
	 *                 <i>Z</i><sup>*</sup><sub><code>n</code><sup>2</sup></sub>
	 * @param viarray  array of verification keys where <code>vi[i]</code> is
	 *                 <code>v</code><sup><code>l</code>!<i>s</i><sub><code>i</code></sub></sup>
	 *                 where <i>s</i><sub><code>i</code></sub> is the private key
	 *                 for decryption server <code>i</code>
	 * @param si       secret share for this server
	 * @param i        ID of the decryption server (from 1 to {@code l})
	 * @param seed     a long integer needed to start a random number generator
	 */
	public PaillierPrivateThresholdKey(BigInteger n, int l, int w,
			BigInteger v, BigInteger[] viarray, BigInteger si, int i, long seed) 
	{
		super(n, l, w, v, viarray, seed);
		this.si = si;
		this.id = i;
	}

	/**
	 * Creates a new private key for the generalized Paillier threshold scheme
	 * from the given modulus <code>n</code>, for use on <code>l</code>
	 * decryption servers, <code>w</code> of which are needed to decrypt
	 * any message encrypted by using this private key.  The values
	 * <code>v</code> and <code>vi</code> correspond to the public
	 * values <i>v</i> and
	 * <i>v<sub>i</sub></i>=<i>v</i><sup><i>l</i>!<i>s<sub>i</sub></i></sup>
	 * needed to verify the zero knowledge proofs.  {@code si} is the secret share
	 * for this decryption key, and {@code i} is the ID.
	 * 
	 * @param n        a safe prime product of <i>p</i> and <i>q</i> where
	 *                 <i>p'</i>=(<i>p</i>-1)/2 and <i>a'</i>=(<i>a</i>-1)/2
	 *                 are also both primes
	 * @param l        number of decryption servers
	 * @param combineSharesConstant
	 *                 precomputed value (4<code>*l</code>!)<sup>-1</sup>
	 *                 mod <code>n</code>
	 * @param w        threshold of servers needed to successfully decrypt any
	 *                 ciphertext created by this public key.  Note that
	 *                 <code>w</code>&le;<code>l</code>/2.
	 * @param v        a generator of a cyclic group of squares in
	 *                 <i>Z</i><sup>*</sup><sub><code>n</code><sup>2</sup></sub>
	 * @param viarray  array of verification keys where <code>vi[i]</code> is
	 *                 <code>v</code><sup><code>l</code>!<i>s</i><sub><code>i</code></sub></sup>
	 *                 where <i>s</i><sub><code>i</code></sub> is the private key
	 *                 for decryption server <code>i</code>
	 * @param si       secret share for this server
	 * @param i        ID of the decryption server (from 1 to {@code l})
	 * @param seed     a long integer needed to start a random number generator
	 */
	public PaillierPrivateThresholdKey(BigInteger n, int l,
			BigInteger combineSharesConstant, int w, BigInteger v,
			BigInteger[] viarray, BigInteger si, int i, long seed) {
		super(n, l, combineSharesConstant, w, v, viarray, seed);
		this.si = si;
		this.id = i;
	}

	/**
	 * Creates a new private key using a byte encoding of a key.
	 * 
	 * @param b			Byte array of the necessary values of this private key
	 * @param seed		a long integer needed to start a random number generator
	 * 
	 * @see #toByteArray()
	 */
	public PaillierPrivateThresholdKey(byte[] b, long seed) {
		super(ByteUtils.getLowerLayer(b), seed);
		int offset = ByteUtils.getInt(b, b.length-4);
		
		this.id = ByteUtils.getInt(b, offset);
		offset += 4;
		
		this.si = ByteUtils.getBigInt(b, offset+4, ByteUtils.getInt(b, offset));
	}
	
	/*
	 * 
	 * Methods
	 * 
	 */
	
	/**
	 * Describes if this key can be used to encrypt
	 * @return     'true' if it can encrypt.
	 */
	public boolean canEncrypt() {
		return true;
	}

	/**
	 * Returns the secret share key which corresponds to this
	 * private key package.  This was generated and given to this
	 * decryption server.
	 * 
	 * @return     secret share of this decryption server
	 */
	public BigInteger getSi() {
		return si;
	}
	
	/**
	 * Returns the id of this private key.  Mostly used to identify
	 * which verification key in {@link #vi} corresponds with this
	 * private key.
	 * 
	 * @return		ID of the decryption server's private key
	 */
	public int getID() {
		return id;
	}
	
	/**
	 * Encodes this key into a byte array.  As this is a public threshold key,
	 * the public modulo {@code n}, {@code l}, {@code w}, {@code v}, 
	 * {@code vi}, {@code id}, and {@code si} will be encoded in that order.
	 * Further, before each BigInteger (except {@code n}) is the 4-byte
	 * equivalent to the size of the BigInteger for later parsing.
	 * 
	 * @return			A byte array containing the most necessary values
	 * 					of this key.  A byte array of size 0 is returned
	 * 					if the key would be too large.
	 * 
	 * @see #PaillierPrivateThresholdKey(byte[], long)
	 * @see BigInteger#toByteArray()
	 */
	public byte[] toByteArray() {
		// The encoding would be:
		// [ prev. layer ]
		// [ id ]
		// [ size of si ]
		// [ si ]
		// [ length of previous layer ]
		
		byte[] p = super.toByteArray();
		
		byte[] r = ByteUtils.appendInt(p, id);
		r = ByteUtils.appendBigInt(r, si);
		r = ByteUtils.appendInt(r, p.length);
		
		return r;
		
//		byte[] si = this.si.toByteArray();
//		
//		byte[] r;
//		
//		//Halt if this doesn't work.
//		if (p.length+si.length+12 > Integer.MAX_VALUE) {
//			r = new byte[0];
//		} else {
//			r = new byte[p.length + si.length + 12];
//				// to account for previous layer, si,
//				//		size of si, id, and length of prev layer
//					
//			System.arraycopy(p, 0,
//					r, 0, p.length);
//			System.arraycopy(intToByte(id), 0,
//					r, p.length, 4);
//			System.arraycopy(intToByte(si.length), 0,
//					r, p.length+4, 4);
//			System.arraycopy(si, 0,
//					r, p.length+4+4, si.length);
//			System.arraycopy(intToByte(p.length), 0,
//					r, p.length+4+4+si.length, 4);
//		}
//		return r;
	}
}
