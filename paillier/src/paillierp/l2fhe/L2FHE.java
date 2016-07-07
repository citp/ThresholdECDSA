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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateKey;

public class L2FHE extends Paillier {

	// CHECK BOTH WITH ROSARIO
	BigInteger fixedRandomnessModN = BigInteger.valueOf(1);
	BigInteger fixedRandomnessModNStar = BigInteger.valueOf(1);

	/**
	 * Default constructor. This constructor can be used if there is no need to
	 * generate public/private key pair.
	 */
	public L2FHE() {
		super();
	}

	/**
	 * Constructs a new encryption object which uses the specified key for
	 * encryption.
	 * 
	 * @param key
	 *            Public key used for encryption
	 */
	public L2FHE(PaillierKey key) {
		super(key);
	}

	/**
	 * Constructs a new encryption/decryption object which uses the specified
	 * key for both encryption and decryption.
	 * 
	 * @param key
	 *            Private key used for decryption and encryption
	 */
	public L2FHE(PaillierPrivateKey key) {
		super(key);
	}

	public L1Ciphertext encrypt1(BigInteger m, BigInteger r, BigInteger b) {
		BigInteger a = m.subtract(b).mod(key.getN());
		BigInteger beta = super.encrypt(b, r);
		return new L1Ciphertext(a, beta);

	}

	public L1Ciphertext encrypt1(BigInteger m) {
		return encrypt1(m, key.getRandomModNStar(), key.getRandomModN());
	}

	public L1Ciphertext encrypt1(BigInteger m, BigInteger r) {
		return encrypt1(m, r, key.getRandomModN());
	}

	public L1Ciphertext fixedRandomnessEncrypt(BigInteger m) {
		return encrypt1(m, fixedRandomnessModNStar, fixedRandomnessModN);
	}

	public L1Ciphertext add(L1Ciphertext c1, L1Ciphertext c2) {
		return new L1Ciphertext(c1.a.add(c2.a).mod(key.getN()), super.add(
				c1.beta, c2.beta));
	}

	public L2Ciphertext add(L2Ciphertext c1, L2Ciphertext c2) {
		BigInteger alpha = super.add(c1.alpha, c2.alpha);
		ArrayList<BigInteger[]> beta = new ArrayList<BigInteger[]>();
		beta.addAll(c1.beta);
		beta.addAll(c2.beta);
		return new L2Ciphertext(alpha, beta);
	}

	public L2Ciphertext add(L1Ciphertext c1, L2Ciphertext c2) {
		return add(mult(c1,fixedRandomnessEncrypt(BigInteger.ONE)),c2);
	}

	public L2Ciphertext mult(L1Ciphertext c1, L1Ciphertext c2) {
		BigInteger alpha = super.add(super.add(super.encrypt(c1.a
				.multiply(c2.a).mod(key.getN()), fixedRandomnessModNStar),
				super.multiply(c2.beta, c1.a)), super.multiply(c1.beta, c2.a));
		ArrayList<BigInteger[]> beta = new ArrayList<>();
		beta.add(new BigInteger[] { c1.beta, c2.beta });
		return new L2Ciphertext(alpha, beta);
	}

	public L1Ciphertext cMult(L1Ciphertext c, BigInteger n) {
		return new L1Ciphertext(c.a.multiply(n), super.multiply(c.beta, n));
	}

	public L2Ciphertext cMult(L2Ciphertext c, BigInteger n) {
		BigInteger alpha = super.multiply(c.alpha, n);
		ArrayList<BigInteger[]> beta = new ArrayList<>();
		for (BigInteger[] betaI : c.beta) {
			beta.add(new BigInteger[] { super.multiply(betaI[0], n), betaI[1] });
		}
		return new L2Ciphertext(alpha, beta);
	}

	public BigInteger decrypt(L1Ciphertext c) {
		return c.a.add(super.decrypt(c.beta)).mod(key.getN());
	}

	public BigInteger decrypt(L2Ciphertext c) {
		BigInteger message = super.decrypt(c.alpha);
		for (BigInteger[] betaI : c.beta) {
			message = message.add(super.decrypt(betaI[0]).multiply(
					super.decrypt(betaI[1])));

		}
		return message.mod(key.getN());

	}

	public L1Ciphertext rerand(L1Ciphertext c) {
		BigInteger b = key.getRandomModN();
		return new L1Ciphertext(c.a.subtract(b), super.add(super.encrypt(b),
				c.beta));
	}

	// public L2Ciphertext rerand(L2Ciphertext c) {
	// BigInteger[][] bTilde = new BigInteger[c.beta.size()][2];
	// for(BigInteger[] bTildeI : bTilde) {
	// bTildeI[0] = key.getRandomModN();
	// bTildeI[1] = key.getRandomModN();
	// }
	// BigInteger[] gamma = new BigInteger[c.beta.size()];
	// for(int i = 0; i < gamma.length; i++) {
	// gamma[i] = super.encrypt(bTilde[i][1].multiply(bTilde[i][2]));
	// }

	// }

	public static void main(String[] args) {
		PaillierPrivateKey key = KeyGen.PaillierKey(512,
				new SecureRandom().nextLong());
		L2FHE l = new L2FHE(key);
		BigInteger msg1 = BigInteger.TEN;
		BigInteger msg2 = BigInteger.valueOf(2);
		BigInteger msg3 = BigInteger.valueOf(3);

		L1Ciphertext c1 = l.encrypt1(msg1);
		L1Ciphertext c2 = l.encrypt1(msg2);
		L1Ciphertext c3 = l.encrypt1(msg3);

		L2Ciphertext c4 = l.mult(l.add(c1, c2), c3);
		L2Ciphertext c5 = l.add(c4, c4);

		System.out.println(l.decrypt(c4));
		System.out.println(l.decrypt(c5));
		System.out.println((msg1.add(msg2)).multiply(msg3));

	}
}
