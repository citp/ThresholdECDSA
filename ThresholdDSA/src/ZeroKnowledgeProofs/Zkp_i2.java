package ZeroKnowledgeProofs;

import static thresholdDSA.Util.getBytes;
import static thresholdDSA.Util.randomFromZn;
import static thresholdDSA.Util.randomFromZnStar;
import static thresholdDSA.Util.sha256Hash;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import thresholdDSA.data.BitcoinParams;

public class Zkp_i2 {

	private ECPoint u1;
	private BigInteger u2;
	private BigInteger u3;
	private BigInteger z1;
	private BigInteger z2;
	private BigInteger s1;
	private BigInteger s2;
	private BigInteger t1;
	private BigInteger t2;
	private BigInteger t3;
	private BigInteger e;
	private BigInteger v1;
	private BigInteger v2;
	private BigInteger v3;

	public Zkp_i2(PublicParameters params, BigInteger eta1, BigInteger eta2,
			SecureRandom rand, ECPoint c, BigInteger w, BigInteger u,
			BigInteger randomness) {

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
		BigInteger delta = randomFromZn(q.pow(3), rand);
		BigInteger mu = randomFromZnStar(N, rand);
		BigInteger nu = randomFromZn(q.pow(3).multiply(nTilde), rand);
		BigInteger theta = randomFromZn(q.pow(8), rand);
		BigInteger tau = randomFromZn(q.pow(8).multiply(nTilde), rand);

		BigInteger rho1 = randomFromZn(q.multiply(nTilde), rand);
		BigInteger rho2 = randomFromZn(q.pow(6).multiply(nTilde), rand);

		z1 = h1.modPow(eta1, nTilde).multiply(h2.modPow(rho1, nTilde))
				.mod(nTilde);
		z2 = h1.modPow(eta2, nTilde).multiply(h2.modPow(rho2, nTilde))
				.mod(nTilde);
		u1 = c.multiply(alpha);
		u2 = g.modPow(alpha, nSquared).multiply(beta.modPow(N, nSquared))
				.mod(nSquared);
		u3 = h1.modPow(alpha, nTilde).multiply(h2.modPow(gamma, nTilde))
				.mod(nTilde);
		v1 = u.modPow(alpha, nSquared)
				.multiply(g.modPow(q.multiply(theta), nSquared))
				.multiply(mu.modPow(N, nSquared)).mod(nSquared);
		v2 = h1.modPow(delta, nTilde).multiply(h2.modPow(nu, nTilde))
				.mod(nTilde);
		v3 = h1.modPow(theta, nTilde).multiply(h2.modPow(tau, nTilde))
				.mod(nTilde);

		byte[] digest = sha256Hash(getBytes(c), getBytes(w), getBytes(u),
				getBytes(z1), getBytes(z2), getBytes(u1), getBytes(u2),
				getBytes(u3), getBytes(v1), getBytes(v2), getBytes(v3));

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta1).add(alpha);
		s2 = e.multiply(rho1).add(gamma);
		t1 = randomness.modPow(e, N).multiply(mu).mod(N);
		t2 = e.multiply(eta2).add(theta);
		t3 = e.multiply(rho2).add(tau);
	}

	public boolean verify(PublicParameters params, ECDomainParameters CURVE,
			ECPoint r, BigInteger u, BigInteger w) {

		ECPoint c = params.getG(CURVE);

		BigInteger h1 = params.h1;
		BigInteger h2 = params.h2;
		BigInteger N = params.paillierPubKey.getN();
		BigInteger nTilde = params.nTilde;
		BigInteger nSquared = N.multiply(N);
		BigInteger g = N.add(BigInteger.ONE);
		BigInteger q = BitcoinParams.q;

		if (!u1.equals(c.multiply(s1).add(r.multiply(e.negate())))) {
			return false;
		}

		if (!u3.equals(h1.modPow(s1, nTilde).multiply(h2.modPow(s2, nTilde))
				.multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde))) {
			return false;
		}

		if (!v1.equals(u.modPow(s1, nSquared)
				.multiply(g.modPow(q.multiply(t2), nSquared))
				.multiply(t1.modPow(N, nSquared))
				.multiply(w.modPow(e.negate(), nSquared)).mod(nSquared))) {
			return false;
		}

		if (!v3.equals(h1.modPow(t2, nTilde).multiply(h2.modPow(t3, nTilde))
				.multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde))) {
			return false;
		}

		byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(w),
				getBytes(u), getBytes(z1), getBytes(z2), getBytes(u1),
				getBytes(u2), getBytes(u3), getBytes(v1), getBytes(v2),
				getBytes(v3));

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
