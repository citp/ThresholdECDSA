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
package ACNS.thresholdDSA;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import ACNS.ZeroKnowledgeProofs.PublicParameters;

public class Util {
	public static BigInteger randomFromZn(BigInteger n, Random rand) {
		BigInteger result;
		do {
			result = new BigInteger(n.bitLength(), rand);
			// check that it's in Zn
		} while (result.compareTo(n) != -1);
		return result;
	}

	public static boolean verifySignature(byte[] message, BigInteger r,
			BigInteger s, byte[] pub, ECDomainParameters Curve) {
		ECDSASigner signer = new ECDSASigner();
		ECPublicKeyParameters params = new ECPublicKeyParameters(Curve
				.getCurve().decodePoint(pub), Curve);
		signer.init(false, params);
		try {
			return signer.verifySignature(message, r, s);
		} catch (NullPointerException e) {
			// Bouncy Castle contains a bug that can cause NPEs given specially
			// crafted signatures. Those signatures
			// are inherently invalid/attack sigs so we just fail them here
			// rather than crash the thread.
			System.out.println("Caught NPE inside bouncy castle");
			e.printStackTrace();
			return false;
		}
	}

	// modified from bitcoinj ECKEy
	@SuppressWarnings("deprecation")
	public static ECPoint compressPoint(ECPoint uncompressed,
			ECDomainParameters CURVE) {
		return new ECPoint.Fp(CURVE.getCurve(), uncompressed.getX(),
				uncompressed.getY(), true);
	}

	/**
	 * Method taken (renamed) from SpongyCastle ECDSASigner class. Cannot call
	 * from there since it's private and non static.
	 */
	public static BigInteger calculateMPrime(BigInteger n, byte[] message) {
		if (n.bitLength() > message.length * 8) {
			return new BigInteger(1, message);
		} else {
			int messageBitLength = message.length * 8;
			BigInteger trunc = new BigInteger(1, message);

			if (messageBitLength - n.bitLength() > 0) {
				trunc = trunc.shiftRight(messageBitLength - n.bitLength());
			}
			return trunc;
		}
	}

	public static boolean isElementOfZn(BigInteger element, BigInteger n) {
		return (element.compareTo(BigInteger.ZERO) != -1)
				&& (element.compareTo(n) == -1);
	}

	/**
	 * Returns an element from Z_n^* randomly selected using the randomness from
	 * {@code rand}
	 * 
	 * @param n
	 *            the modulus
	 */
	public static BigInteger randomFromZnStar(BigInteger n, Random rand) {
		BigInteger result;
		do {
			result = new BigInteger(n.bitLength(), rand);
			// check that it's in Zn*
		} while (result.compareTo(n) != -1
				|| !result.gcd(n).equals(BigInteger.ONE));
		return result;
	}

	public static byte[] sha256Hash(byte[]... inputs) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			for (byte[] input : inputs) {
				md.update(input);
			}
			return md.digest();

		} catch (NoSuchAlgorithmException ex) {
			throw new AssertionError();
		}
	}

	public static byte[] getBytes(BigInteger n) {
		return n.toByteArray();
	}

	@SuppressWarnings("deprecation")
	public static byte[] getBytes(ECPoint e) {
		byte[] x = e.getX().toBigInteger().toByteArray();
		byte[] y = e.getY().toBigInteger().toByteArray();
		byte[] output = new byte[x.length + y.length];
		System.arraycopy(x, 0, output, 0, x.length);
		System.arraycopy(y, 0, output, x.length, y.length);
		return output;
	}

	public static void generatePaillierKeyShares(String filename,
			SecureRandom rnd, int numPlayers, int threshold) throws IOException {
		// A value of 1025 will give us an N of order > 2048. We need N to be
		// O(q^8).
		// Since Bitcoin uses a curve where q is O(2^256), this is big
		// enough
		KeyGen.PaillierThresholdKey(filename, 1023, numPlayers, threshold,
				rnd.nextLong());
	}

	public static PublicParameters generateParamsforBitcoin(int k, int kPrime,
			SecureRandom rand, PaillierKey paillierPubKey) {

		X9ECParameters params = SECNamedCurves.getByName("secp256k1");
		ECDomainParameters CURVE = new ECDomainParameters(params.getCurve(),
				params.getG(), params.getN(), params.getH());

		int primeCertainty = k;
		BigInteger p;
		BigInteger q;
		BigInteger pPrime;
		BigInteger qPrime;
		BigInteger pPrimeqPrime;
		BigInteger nHat;

		do {
			p = new BigInteger(kPrime / 2, primeCertainty, rand);
		} while (!p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
				.isProbablePrime(primeCertainty));

		pPrime = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

		do {
			q = new BigInteger(kPrime / 2, primeCertainty, rand);
		} while (!q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
				.isProbablePrime(primeCertainty));

		qPrime = q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

		// generate nhat. the product of two safe primes, each of length
		// kPrime/2
		nHat = p.multiply(q);

		BigInteger h2 = randomFromZnStar(nHat, rand);
		pPrimeqPrime = pPrime.multiply(qPrime);

		BigInteger x = randomFromZn(pPrimeqPrime, rand);
		BigInteger h1 = h2.modPow(x, nHat);

		return new PublicParameters(CURVE, nHat, h1, h2, paillierPubKey);

	}

	public static byte[] serialize(Serializable obj) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		oos.writeObject(obj);
		return bos.toByteArray();
	}

	public static Object deserialize(byte[] bytes) throws IOException,
			ClassNotFoundException {
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		ObjectInputStream ois = new ObjectInputStream(bis);
		return ois.readObject();

	}
}
