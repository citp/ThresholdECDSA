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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import paillierp.key.KeyGen;

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
	

  


}
