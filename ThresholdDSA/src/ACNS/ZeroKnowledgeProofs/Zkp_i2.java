package ACNS.ZeroKnowledgeProofs;

import static ACNS.thresholdDSA.Util.getBytes;
import static com.squareup.jnagmp.Gmp.modPowInsecure;
import static ACNS.thresholdDSA.Util.randomFromZn;
import static ACNS.thresholdDSA.Util.randomFromZnStar;
import static ACNS.thresholdDSA.Util.sha256Hash;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import ACNS.thresholdDSA.data.BitcoinParams;

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

		z1 = modPowInsecure(h1,eta1, nTilde).multiply(modPowInsecure(h2,rho1, nTilde))
				.mod(nTilde);
		z2 = modPowInsecure(h1,eta2, nTilde).multiply(modPowInsecure(h2,rho2, nTilde))
				.mod(nTilde);
		u1 = c.multiply(alpha);
		u2 = modPowInsecure(g,alpha, nSquared).multiply(modPowInsecure(beta,N, nSquared))
				.mod(nSquared);
		u3 = modPowInsecure(h1,alpha, nTilde).multiply(modPowInsecure(h2,gamma, nTilde))
				.mod(nTilde);
		v1 = modPowInsecure(u,alpha, nSquared)
				.multiply(modPowInsecure(g,q.multiply(theta), nSquared))
				.multiply(modPowInsecure(mu,N, nSquared)).mod(nSquared);
		v3 = modPowInsecure(h1,theta, nTilde).multiply(modPowInsecure(h2,tau, nTilde))
				.mod(nTilde);

		byte[] digest = sha256Hash(getBytes(c), getBytes(w), getBytes(u),
				getBytes(z1), getBytes(z2), getBytes(u1), getBytes(u2),
				getBytes(u3), getBytes(v1), getBytes(v3));

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta1).add(alpha);
		s2 = e.multiply(rho1).add(gamma);
		t1 = modPowInsecure(randomness,e, N).multiply(mu).mod(N);
		t2 = e.multiply(eta2).add(theta);
		t3 = e.multiply(rho2).add(tau);
	}

	public boolean verify(PublicParameters params, ECDomainParameters CURVE,
			final ECPoint r, final BigInteger u, final BigInteger w) {

		final ECPoint c = params.getG(CURVE);

		final BigInteger h1 = params.h1;
		final BigInteger h2 = params.h2;
		final BigInteger N = params.paillierPubKey.getN();
		final BigInteger nTilde = params.nTilde;
		final BigInteger nSquared = N.multiply(N);
		final BigInteger g = N.add(BigInteger.ONE);
		final BigInteger q = BitcoinParams.q;
		
		
		ExecutorService executor = Executors.newCachedThreadPool();

		int numTests = 5;
		List<Callable<Boolean>> tests = new ArrayList<Callable<Boolean>>(
				numTests);
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u1.equals(c.multiply(s1).add(r.multiply(e.negate())));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u3.equals(modPowInsecure(h1,s1, nTilde).multiply(modPowInsecure(h2,s2, nTilde))
						.multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v1.equals(modPowInsecure(u,s1, nSquared)
						.multiply(modPowInsecure(g,q.multiply(t2), nSquared))
						.multiply(modPowInsecure(t1,N, nSquared))
						.multiply(w.modPow(e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v3.equals(modPowInsecure(h1,t2, nTilde).multiply(modPowInsecure(h2,t3, nTilde))
						.multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(w),
						getBytes(u), getBytes(z1), getBytes(z2), getBytes(u1),
						getBytes(u2), getBytes(u3), getBytes(v1),
						getBytes(v3));

				if (digestRecovered == null) {
					return false;
				}

				BigInteger eRecovered = new BigInteger(1, digestRecovered);

				return eRecovered.equals(e);
			}
		});
		
List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>(numTests);
		
		for(Callable<Boolean> test: tests) {
			futures.add(executor.submit(test));	
		}
		
		for(Future<Boolean> future: futures) {
			try {
				if(!future.get().booleanValue()) {
					return false;
				}
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			} catch (ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
		}
	
		executor.shutdown();
		return true;
	

//		if (!u1.equals(c.multiply(s1).add(r.multiply(e.negate())))) {
//			return false;
//		}
//
//		if (!u3.equals(h1.modPow(s1, nTilde).multiply(h2.modPow(s2, nTilde))
//				.multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde))) {
//			return false;
//		}
//		
//		// VERIFY U2!!!
//
//		if (!v1.equals(u.modPow(s1, nSquared)
//				.multiply(g.modPow(q.multiply(t2), nSquared))
//				.multiply(t1.modPow(N, nSquared))
//				.multiply(w.modPow(e.negate(), nSquared)).mod(nSquared))) {
//			return false;
//		}
//
//		if (!v3.equals(h1.modPow(t2, nTilde).multiply(h2.modPow(t3, nTilde))
//				.multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde))) {
//			return false;
//		}
//
//		byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(w),
//				getBytes(u), getBytes(z1), getBytes(z2), getBytes(u1),
//				getBytes(u2), getBytes(u3), getBytes(v1),
//				getBytes(v3));
//
//		if (digestRecovered == null) {
//			return false;
//		}
//
//		BigInteger eRecovered = new BigInteger(1, digestRecovered);
//
//		if (!eRecovered.equals(e)) {
//			return false;
//		}
//		return true;
	}

}
