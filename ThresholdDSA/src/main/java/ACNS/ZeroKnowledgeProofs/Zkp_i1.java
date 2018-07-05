package ACNS.ZeroKnowledgeProofs;

import static ACNS.thresholdDSA.Util.getBytes;
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

import ACNS.thresholdDSA.data.BitcoinParams;
import static com.squareup.jnagmp.Gmp.modPowInsecure;
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

		z = modPowInsecure(h1,eta, nTilde).multiply(modPowInsecure(h2,rho, nTilde)).mod(nTilde);
		u1 = modPowInsecure(g,alpha, nSquared).multiply(modPowInsecure(beta,N, nSquared))
				.mod(nSquared);
		u2 = modPowInsecure(h1,alpha, nTilde).multiply(modPowInsecure(h2,gamma, nTilde)).mod(nTilde);
		v = modPowInsecure(c2,alpha, nSquared);

		byte[] digest = sha256Hash(getBytes(c1), getBytes(c2), getBytes(c3),
				getBytes(z), getBytes(u1), getBytes(u2), getBytes(v));

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta).add(alpha);
		s2 = modPowInsecure(r,e, N).multiply(beta).mod(N);
		s3 = e.multiply(rho).add(gamma);

	}

	public boolean verify(PublicParameters params, ECDomainParameters CURVE,
			  final BigInteger c1, final BigInteger c2, final BigInteger c3) {

		final BigInteger h1 = params.h1;
		final BigInteger h2 = params.h2;
		final BigInteger N = params.paillierPubKey.getN();
		final BigInteger nTilde = params.nTilde;
		final BigInteger nSquared = N.pow(2);
		final BigInteger g = N.add(BigInteger.ONE);
		
		ExecutorService executor = Executors.newCachedThreadPool();

		int numTests = 4;
		List<Callable<Boolean>> tests = new ArrayList<Callable<Boolean>>(
				numTests);
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u1.equals(modPowInsecure(g,s1, nSquared).multiply(modPowInsecure(s2,N, nSquared))
						.multiply(c3.modPow(e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u2.equals(modPowInsecure(h1,s1, nTilde).multiply(modPowInsecure(h2,s3, nTilde))
						.multiply(z.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v.equals(modPowInsecure(c2,s1, nSquared)
						.multiply(c1.modPow(e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				byte[] digestRecovered = sha256Hash(getBytes(c1), getBytes(c2), getBytes(c3),
						getBytes(z), getBytes(u1), getBytes(u2), getBytes(v));

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
		
		
		

		
		
//		if (!u1.equals(g.modPow(s1, nSquared).multiply(s2.modPow(N, nSquared))
//				.multiply(c3.modPow(e.negate(), nSquared)).mod(nSquared))) {
//			return false;
//		}
//
//		if (!u2.equals(h1.modPow(s1, nTilde).multiply(h2.modPow(s3, nTilde))
//				.multiply(z.modPow(e.negate(), nTilde)).mod(nTilde))) {
//			return false;
//		}
//		
//		if (!v.equals(c2.modPow(s1, nSquared)
//				.multiply(c1.modPow(e.negate(), nSquared)).mod(nSquared))) {
//			return false;
//		}
//
//		
//
//		byte[] digestRecovered = sha256Hash(getBytes(c1), getBytes(c2), getBytes(c3),
//				getBytes(z), getBytes(u1), getBytes(u2), getBytes(v));
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
