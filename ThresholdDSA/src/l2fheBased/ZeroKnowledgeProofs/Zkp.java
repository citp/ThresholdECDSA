/*
 * Copyright 2013 Matija Mazi.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
package l2fheBased.ZeroKnowledgeProofs;

import static ACNS.thresholdDSA.Util.getBytes;

import static ACNS.thresholdDSA.Util.randomFromZn;
import static ACNS.thresholdDSA.Util.randomFromZnStar;
import static ACNS.thresholdDSA.Util.sha256Hash;
import static com.squareup.jnagmp.Gmp.modPowInsecure;
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

import paillierp.key.PaillierKey;
import paillierp.l2fhe.L1Ciphertext;
import ACNS.ZeroKnowledgeProofs.PublicParameters;
import ACNS.thresholdDSA.data.BitcoinParams;

public class Zkp {

	private ECPoint u1;
	private BigInteger u2;
	private BigInteger u3;
	private BigInteger u4;
	private BigInteger v1;
	private BigInteger v2;
	private BigInteger v3;
	private BigInteger z1;
	private BigInteger z2;
	private BigInteger z3;
	private BigInteger s1;
	private BigInteger t1;
	private BigInteger t2;
	private BigInteger t3;
	private BigInteger s3;
	private BigInteger s4;
	private BigInteger s5;
	private BigInteger s6;
	private BigInteger s7;
	private BigInteger e;

	final BigInteger w1;
	final BigInteger w2;
	final BigInteger w3;

	public Zkp(PublicParameters params, BigInteger eta1, BigInteger eta2,
			BigInteger eta3, SecureRandom rand, ECPoint c, ECPoint r,
			L1Ciphertext w1FHE, L1Ciphertext w2FHE, L1Ciphertext w3FHE,
			BigInteger w1, BigInteger w2, BigInteger w3,
			BigInteger randomness1, BigInteger randomness2,
			BigInteger randomness3) {

		this.w1 = w1;
		this.w2 = w2;
		this.w3 = w3;

		BigInteger N = params.paillierPubKey.getNS();

		BigInteger q = BitcoinParams.q;
		BigInteger nSquared = params.paillierPubKey.getNSPlusOne();
		BigInteger nTilde = params.nTilde;
		BigInteger h1 = params.h1;
		BigInteger h2 = params.h2;
		BigInteger g = params.paillierPubKey.getNPlusOne();

		BigInteger alpha1 = randomFromZn(q.pow(3), rand);
		BigInteger alpha2 = randomFromZn(q.pow(3), rand);
		BigInteger alpha3 = randomFromZn(q.pow(7), rand);

		BigInteger beta1 = randomFromZnStar(N, rand);
		BigInteger beta2 = randomFromZnStar(N, rand);
		BigInteger beta3 = randomFromZnStar(N, rand);

		BigInteger gamma1 = randomFromZn(q.pow(3).multiply(nTilde), rand);
		BigInteger gamma2 = randomFromZn(q.pow(3).multiply(nTilde), rand);
		BigInteger gamma3 = randomFromZn(q.pow(7).multiply(nTilde), rand);

		BigInteger rho1 = randomFromZn(q.multiply(nTilde), rand);
		BigInteger rho2 = randomFromZn(q.multiply(nTilde), rand);
		BigInteger rho3 = randomFromZn(q.pow(5).multiply(nTilde), rand);

		z1 =modPowInsecure(h1,eta1, nTilde).multiply(modPowInsecure(h2,rho1, nTilde))
				.mod(nTilde);
		z2 = modPowInsecure(h1,eta2, nTilde).multiply(modPowInsecure(h2,rho2, nTilde))
				.mod(nTilde);
		z3 = modPowInsecure(h1,eta3, nTilde).multiply(modPowInsecure(h2,rho3, nTilde))
				.mod(nTilde);

		u1 = c.multiply(alpha1);
		u2 = modPowInsecure(g,alpha1, nSquared).multiply(modPowInsecure(beta1,N, nSquared))
				.mod(nSquared);

		u3 = modPowInsecure(g,alpha2, nSquared).multiply(modPowInsecure(beta2,N, nSquared))
				.mod(nSquared);
		u4 = modPowInsecure(g,alpha3, nSquared).multiply(modPowInsecure(beta3,N, nSquared))
				.mod(nSquared);

		v1 = modPowInsecure(h1,alpha1, nTilde).multiply(modPowInsecure(h2,gamma1, nTilde))
				.mod(nTilde);
		v2 = modPowInsecure(h1,alpha2, nTilde).multiply(modPowInsecure(h2,gamma2, nTilde))
				.mod(nTilde);
		v3 = modPowInsecure(h1,alpha3, nTilde).multiply(modPowInsecure(h2,gamma3, nTilde))
				.mod(nTilde);

		byte[] digest = sha256Hash(getBytes(c), getBytes(r), getBytes(w1FHE.a),
				getBytes(w1FHE.beta), getBytes(w2FHE.a), getBytes(w2FHE.beta),
				getBytes(w3FHE.a), getBytes(w3FHE.beta), getBytes(z1),
				getBytes(u1), getBytes(u2), getBytes(u3), getBytes(u4),
				getBytes(v1), getBytes(v2), getBytes(v3));

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta1).add(alpha1);
		t1 = modPowInsecure(randomness1,e, N).multiply(beta1).mod(N);
		t2 = modPowInsecure(randomness2,e, N).multiply(beta2).mod(N);
		t3 = modPowInsecure(randomness3,e, N).multiply(beta3).mod(N);

		s3 = e.multiply(rho1).add(gamma1);

		s4 = e.multiply(eta2).add(alpha2);
		s5 = e.multiply(rho2).add(gamma2);

		s6 = e.multiply(eta3).add(alpha3);
		s7 = e.multiply(rho3).add(gamma3);

	}

	public boolean verify(final PublicParameters params,
			ECDomainParameters CURVE, final ECPoint r,
			final L1Ciphertext w1FHE, final L1Ciphertext w2FHE,
			final L1Ciphertext w3FHE) {

		final ECPoint c = params.getG(CURVE);

		final BigInteger h1 = params.h1;
		final BigInteger h2 = params.h2;
		final BigInteger N = params.paillierPubKey.getNS();
		final BigInteger nTilde = params.nTilde;
		final BigInteger nSquared = params.paillierPubKey.getNSPlusOne();
		final PaillierKey key = params.paillierPubKey.getPublicKey();

		final BigInteger gamma = N.add(BigInteger.ONE);

		ExecutorService executor = Executors.newCachedThreadPool();

		int numTests = 11;
		List<Callable<Boolean>> tests = new ArrayList<Callable<Boolean>>(11);

		// Callable<BigInteger> w1t = new Callable<BigInteger>() {
		// @Override
		// public BigInteger call() {
		// return w1.toPaillierCiphertext(key);
		// }
		// };
		//
		// Callable<BigInteger> w2t = new Callable<BigInteger>() {
		// @Override
		// public BigInteger call() {
		// return w2.toPaillierCiphertext(key);
		// }
		// };
		//
		// Callable<BigInteger> w3t = new Callable<BigInteger>() {
		// @Override
		// public BigInteger call() {
		// return w3.toPaillierCiphertext(key);
		// }
		// };
		//
		// final Future<BigInteger> w1val = executor.submit(w1t);
		// final Future<BigInteger> w2val = executor.submit(w2t);
		// final Future<BigInteger> w3val = executor.submit(w3t);

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return w1.equals(w1FHE.toPaillierCiphertext(key));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return w2.equals(w2FHE.toPaillierCiphertext(key));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return w3.equals(w3FHE.toPaillierCiphertext(key));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u1.equals(c.multiply(s1).add(r.multiply(e.negate())));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u2.equals(modPowInsecure(gamma,s1, nSquared)
						.multiply(modPowInsecure(t1,N, nSquared))
						.multiply(w1.modPow(e.negate(), nSquared))
						.mod(nSquared));

			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u3.equals(modPowInsecure(gamma,s4, nSquared)
						.multiply(modPowInsecure(t2,N, nSquared))
						.multiply(w2.modPow(e.negate(), nSquared))
						.mod(nSquared));

			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u4.equals(modPowInsecure(gamma,s6, nSquared)
						.multiply(modPowInsecure(t3,N, nSquared))
						.multiply(w3.modPow(e.negate(), nSquared))
						.mod(nSquared));

			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v1.equals(modPowInsecure(h1,s1, nTilde)
						.multiply(modPowInsecure(h2,s3, nTilde))
						.multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v2.equals(modPowInsecure(h1,s4, nTilde)
						.multiply(modPowInsecure(h2,s5, nTilde))
						.multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v3.equals(modPowInsecure(h1,s6, nTilde)
						.multiply(modPowInsecure(h2,s7, nTilde))
						.multiply(z3.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});

		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				byte[] digestRecovered = null;
				digestRecovered = sha256Hash(getBytes(c), getBytes(r),
						getBytes(w1FHE.a), getBytes(w1FHE.beta),
						getBytes(w2FHE.a), getBytes(w2FHE.beta),
						getBytes(w3FHE.a), getBytes(w3FHE.beta), getBytes(z1),
						getBytes(u1), getBytes(u2), getBytes(u3), getBytes(u4),
						getBytes(v1), getBytes(v2), getBytes(v3));

				if (digestRecovered == null) {
					return false;
				}

				BigInteger eRecovered = new BigInteger(1, digestRecovered);

				return eRecovered.equals(e);
			}
		});

		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>(numTests);

		for (Callable<Boolean> test : tests) {
			futures.add(executor.submit(test));
		}

		for (Future<Boolean> future : futures) {
			try {
				if (!future.get().booleanValue()) {
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

		// if (!u1.equals(c.multiply(s1).add(r.multiply(e.negate())))) {
		// return false;
		// }
		//
		// if (!u2.equals(gamma.modPow(s1, nSquared)
		// .multiply(t1.modPow(N, nSquared))
		// .multiply(w1.modPow(e.negate(), nSquared)).mod(nSquared))) {
		// return false;
		// }
		//
		// if (!u3.equals(gamma.modPow(s4, nSquared)
		// .multiply(t2.modPow(N, nSquared))
		// .multiply(w2.modPow(e.negate(), nSquared)).mod(nSquared))) {
		// return false;
		// }
		//
		// if (!u4.equals(gamma.modPow(s6, nSquared)
		// .multiply(t3.modPow(N, nSquared))
		// .multiply(w3.modPow(e.negate(), nSquared)).mod(nSquared))) {
		// return false;
		// }
		//
		// if (!v1.equals(h1.modPow(s1, nTilde).multiply(h2.modPow(s3, nTilde))
		// .multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde))) {
		// return false;
		// }
		//
		// if (!v2.equals(h1.modPow(s4, nTilde).multiply(h2.modPow(s5, nTilde))
		// .multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde))) {
		// return false;
		// }
		//
		// if (!v3.equals(h1.modPow(s6, nTilde).multiply(h2.modPow(s7, nTilde))
		// .multiply(z3.modPow(e.negate(), nTilde)).mod(nTilde))) {
		// return false;
		// }
		//
		// byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(r),
		// getBytes(w1), getBytes(w2), getBytes(w3), getBytes(z1),
		// getBytes(u1), getBytes(u2), getBytes(u3), getBytes(u4),
		// getBytes(v1), getBytes(v2), getBytes(v3));
		//
		// if (digestRecovered == null) {
		// return false;
		// }
		//
		// BigInteger eRecovered = new BigInteger(1, digestRecovered);
		//
		// if (!eRecovered.equals(e)) {
		// return false;
		// }
		// return true;
	}
}