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
 */
package paillierp.l2fhe;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import paillierp.PaillierThreshold;
import paillierp.PartialDecryption;
import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateKey;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.key.PaillierThresholdKey;
import paillierp.zkp.DecryptionZKP;

public class ThresholdL2FHE extends PaillierThreshold {

	/**
	 * Default constructor. This constructor can be used if there is no need to
	 * generate public/private key pair.
	 */
	public ThresholdL2FHE() {
		super();
	}

	/**
	 * Constructs a new encryption object which uses the specified key for
	 * encryption.
	 * 
	 * @param key
	 *            Public key used for encryption
	 */
	public ThresholdL2FHE(PaillierThresholdKey key) {
		super(key);
	}

	/**
	 * Constructs a new encryption/decryption object which uses the specified
	 * key for both encryption and decryption.
	 * 
	 * @param key
	 *            Private key used for decryption and encryption
	 */
	public ThresholdL2FHE(PaillierPrivateThresholdKey key) {
		super(key);
	}

	/**
	 * Constructs a new encryption object which uses the specified key for
	 * encryption.
	 * 
	 * @param key
	 *            Public key used for encryption
	 */
	public ThresholdL2FHE(PaillierKey key) {
		super(key);
	}

	/**
	 * Sets the mode for this object to decrypt and encrypt using the provided
	 * key.
	 * 
	 * @param key
	 *            Private key which this class will use to encrypt and decrypt
	 */
	public void setDecryptEncrypt(PaillierPrivateThresholdKey key) {
		super.setDecryptEncrypt(key);
	}

	/**
	 * The public key of the Paillier threshold system, which includes the
	 * values <i>n</i> and the public values <i>v</i> and
	 * {<i>v<sub>i</sub></i>}. This object must already be in decrypt mode to
	 * return these values.
	 * 
	 * @return The public key <i>n</i> and public values
	 */
	public PaillierThresholdKey getPublicThresholdKey() {
		return super.getPublicThresholdKey();
	}

	/**
	 * The private key for the Paillier system with thresholding is the RSA
	 * modulo n and the secret share <i>s<sub>i</sub></i>
	 * 
	 * @return The private key; null if not in decrypt mode
	 */
	public PaillierPrivateThresholdKey getPrivateKey() {
		return super.getPrivateKey();
	}

	/**
	 * Partially decrypts the given ciphertext {@code c} < <i>n</i><sup>2</sup>
	 * using the share of the private key. Returns only the decrypted value with
	 * no ID attached.
	 * 
	 * @param c
	 *            ciphertext as BigInteger
	 * @return the decrypted share <i>c<sub>i</sub></i>
	 */
	public BigInteger decryptOnly(L1Ciphertext c) {
		return (super.decryptOnly(c.beta));
		// return new L1PartialDecryptOnly(super.decryptOnly(c.beta), c.a);
	}

	// /**
	// * Partially decrypts the given ciphertext {@code c} <
	// <i>n</i><sup>2</sup>
	// * using the share of the private key. Returns only the decrypted value
	// * with no ID attached.
	// *
	// * @param c ciphertext as BigInteger
	// * @return the decrypted share <i>c<sub>i</sub></i>
	// */
	// public L2PartialDecryptOnly decryptOnly(L2Ciphertext c) {
	//
	// }

	/**
	 * Partially decrypts the given ciphertext {@code c} < <i>n</i><sup>2</sup>
	 * using the share of the private key.
	 * 
	 * @param c
	 *            ciphertext as BigInteger
	 * @return the decrypted share <i>c<sub>i</sub></i>
	 */
	public PartialDecryption decrypt(L1Ciphertext c) {
		return super.decrypt(c.beta);
	}

	public L2PartialDecryption decrypt(L2Ciphertext c) {
		PartialDecryption a = super.decrypt(c.alpha);
		PartialDecryption[][] b = new PartialDecryption[c.beta.size()][2];
		for (int i = 0; i < b.length; i++) {
			b[i][0] = super.decrypt(c.beta.get(i)[0]);
			b[i][1] = super.decrypt(c.beta.get(i)[1]);
		}
		return new L2PartialDecryption(a, b);

	}

	/**
	 * Partially decrypts the given ciphertext {@code c} < <i>n</i><sup>2</sup>
	 * using the share of the private key. This then gives a non-interactive
	 * Zero Knowledge Proof that the partial decryption is truly this share's
	 * contribution to the decryption of {@code c}.
	 * 
	 * @param c
	 *            ciphertext as BigInteger
	 * @return the decrypted share <i>c<sub>i</sub></i>
	 */
	public DecryptionZKP decryptProof(L1Ciphertext c) {
		return super.decryptProof(c.beta);
	}

	public L2DecryptionWithZKP decryptProof(L2Ciphertext c) {
		DecryptionZKP a = super.decryptProof(c.alpha);
		DecryptionZKP[][] b = new DecryptionZKP[c.beta.size()][2];
		for (int i = 0; i < b.length; i++) {
			b[i][0] = super.decryptProof(c.beta.get(i)[0]);
			b[i][1] = super.decryptProof(c.beta.get(i)[1]);
		}
		return new L2DecryptionWithZKP(a, b);
	}

	public BigInteger combineShares(BigInteger a, PartialDecryption... shares) {
		BigInteger b = super.combineShares(shares);
		return a.add(b).mod(key.getN());
	}

	public BigInteger combineShares(L2PartialDecryption... shares) {
		PartialDecryption[] aShares = new PartialDecryption[shares.length];
		PartialDecryption[][][] bShares = new PartialDecryption[2][shares[0].b.length][shares.length];
		for (int i = 0; i < shares.length; i++) {
			aShares[i] = shares[i].a;
		}
		for (int i = 0; i < bShares[0].length; i++) {

			for (int j = 0; j < shares.length; j++) {
				bShares[0][i][j] = shares[j].b[i][0];
				bShares[1][i][j] = shares[j].b[i][1];
			}
		}
		BigInteger message = super.combineShares(aShares);
		for(int i = 0; i < shares[0].b.length; i++) {
			message = message.add(super.combineShares(bShares[0][i]).multiply(super.combineShares(bShares[1][i])));
		}
		return message.mod(key.getN());

	}


	public BigInteger combineShares(BigInteger a, DecryptionZKP... shares) {
		BigInteger b = super.combineShares(shares);
		return a.add(b).mod(key.getN());
	}
	
	public BigInteger combineShares(L2DecryptionWithZKP... shares) {
		DecryptionZKP[] aShares = new DecryptionZKP[shares.length];
		DecryptionZKP[][][] bShares = new DecryptionZKP[2][shares[0].b.length][shares.length];
		for (int i = 0; i < shares.length; i++) {
			aShares[i] = shares[i].a;
		}
		for (int i = 0; i < bShares[0].length; i++) {

			for (int j = 0; j < shares.length; j++) {
				bShares[0][i][j] = shares[j].b[i][0];
				bShares[1][i][j] = shares[j].b[i][1];
			}
		}
		BigInteger message = super.combineShares(aShares);
		for(int i = 0; i < shares[0].b.length; i++) {
			message = message.add(super.combineShares(bShares[0][i]).multiply(super.combineShares(bShares[1][i])));
		}
		return message.mod(key.getN());

	}
	
	public static void main(String[] args) {
		
		SecureRandom rnd = new SecureRandom();

		if (!new File("key_2046_3-15").exists()) {
				System.out.println("generating new key");
				try {
					Util.generatePaillierKeyShares("key_2046_3-15", rnd, 15, 3);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}

		PaillierPrivateThresholdKey[] keys = KeyGen
				.PaillierThresholdKeyLoad("key_2046_3-15");

		L2FHE l = new L2FHE(keys[0].getPublicKey());
		
		ThresholdL2FHE p0 = new ThresholdL2FHE(keys[0]);
		ThresholdL2FHE p1 = new ThresholdL2FHE(keys[1]);
		ThresholdL2FHE p2 = new ThresholdL2FHE(keys[2]);

		
		
		
		
		PaillierPrivateKey key = KeyGen.PaillierKey(512, new SecureRandom().nextLong());
		BigInteger msg1 = key.getN().divide(BigInteger.valueOf(16));
		BigInteger msg2 = BigInteger.valueOf(344569);
		BigInteger msg3 = BigInteger.valueOf(2);


		L1Ciphertext c1 = l.encrypt1(msg1);
		L1Ciphertext c2 = l.encrypt1(msg2);
		L1Ciphertext c3 = l.encrypt1(msg3);
		L1Ciphertext c4 = l.add(c1, c2);

		L2Ciphertext c5 = l.mult(c4,c3);

		PartialDecryption d0 = p0.decrypt(c4);
		PartialDecryption d1 = p1.decrypt(c4);
		PartialDecryption d2 = p2.decrypt(c4);
		
		System.out.println(p0.combineShares(c4.a, d0,d1,d2));
		
		L2PartialDecryption cd0 = p0.decrypt(c5);
		L2PartialDecryption cd1 = p1.decrypt(c5);
		L2PartialDecryption cd2 = p2.decrypt(c5);
		
		System.out.println(p0.combineShares(cd0,cd1,cd2));
		System.out.println((msg1.add(msg2)).multiply(msg3));

		L2DecryptionWithZKP cdp0 = p0.decryptProof(c5);
		L2DecryptionWithZKP cdp1 = p1.decryptProof(c5);
		L2DecryptionWithZKP cdp2 = p2.decryptProof(c5);
		
		System.out.println(p0.combineShares(cdp0,cdp1,cdp2));

	}
}
