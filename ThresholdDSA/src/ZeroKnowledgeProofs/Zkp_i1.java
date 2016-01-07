package ZeroKnowledgeProofs;

import static thresholdDSA.Util.getBytes;
import static thresholdDSA.Util.randomFromZn;
import static thresholdDSA.Util.randomFromZnStar;
import static thresholdDSA.Util.sha256Hash;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ECDomainParameters;

import thresholdDSA.data.BitcoinParams;

public class Zkp_i1 {

	private BigInteger z;
	private BigInteger u1;
	private BigInteger u2;
	private BigInteger s1;
	private BigInteger s2;
	private BigInteger s3;
	private BigInteger e;
	private BigInteger v;

	public Zkp_i1(PublicParameters params, BigInteger eta, SecureRandom rand,
			BigInteger r, BigInteger c1, BigInteger c2, BigInteger c3) {
		
		BigInteger N = params.paillierPubKey.getN();
		BigInteger q = BitcoinParams.q;
		BigInteger nSquared = N.multiply(N);
		BigInteger nTilde = params.nTilde;
		BigInteger h1 = params.h1;
		BigInteger h2 = params.h2;
		BigInteger g = N.add(BigInteger.ONE);

		BigInteger alpha = randomFromZn(q.pow(3), rand);
		BigInteger beta = randomFromZnStar(N, rand);
		BigInteger gamma = randomFromZn(q.pow(3).multiply(nTilde), rand);
		BigInteger rho = randomFromZn(q.multiply(nTilde), rand);

		z = h1.modPow(eta, nTilde).multiply(h2.modPow(rho, nTilde)).mod(nTilde);
		u1 = g.modPow(alpha, nSquared).multiply(beta.modPow(N, nSquared))
				.mod(nSquared);
		u2 = h1.modPow(alpha, nTilde).multiply(h2.modPow(gamma, nTilde)).mod(nTilde);
		v = c2.modPow(alpha, nSquared);

		byte[] digest = sha256Hash(getBytes(c1), getBytes(c2), getBytes(c3),
				getBytes(z), getBytes(u1), getBytes(u2), getBytes(v));

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta).add(alpha);
		s2 = r.modPow(e, N).multiply(beta).mod(N);
		s3 = e.multiply(rho).add(gamma);

	}

	public boolean verify(PublicParameters params, ECDomainParameters CURVE,
			  BigInteger c1, BigInteger c2, BigInteger c3) {

		BigInteger h1 = params.h1;
		BigInteger h2 = params.h2;
		BigInteger N = params.paillierPubKey.getN();
		BigInteger nTilde = params.nTilde;
		BigInteger nSquared = N.pow(2);
		BigInteger g = N.add(BigInteger.ONE);
		
		if (!u1.equals(g.modPow(s1, nSquared).multiply(s2.modPow(N, nSquared))
				.multiply(c3.modPow(e.negate(), nSquared)).mod(nSquared))) {
			return false;
		}

		if (!u2.equals(h1.modPow(s1, nTilde).multiply(h2.modPow(s3, nTilde))
				.multiply(z.modPow(e.negate(), nTilde)).mod(nTilde))) {
			return false;
		}
		
		if (!v.equals(c2.modPow(s1, nSquared)
				.multiply(c1.modPow(e.negate(), nSquared)).mod(nSquared))) {
			return false;
		}

		

		byte[] digestRecovered = sha256Hash(getBytes(c1), getBytes(c2), getBytes(c3),
				getBytes(z), getBytes(u1), getBytes(u2), getBytes(v));

		if (digestRecovered == null) {
			return false;
		}

		BigInteger eRecovered = new BigInteger(1, digestRecovered);

		if (!eRecovered.equals(e)) {
			return false;
		}
		return true;
	}

}
