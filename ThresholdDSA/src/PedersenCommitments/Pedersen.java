package PedersenCommitments;

import java.math.BigInteger;
import java.security.SecureRandom;

import thresholdDSA.Util;

public class Pedersen<T> {

	private final T commitment;
	private final Open<T> open;

	public Pedersen(T commitment, Open<T> open) {
		this.commitment = commitment;
		this.open = open;
	}

	public T getCommitment() {
		return commitment;
	}

	public Open<T> getOpen() {
		return open;
	}

	public static boolean checkCommitment(
			PedersenPublicParams<BigInteger> params, BigInteger commitment,
			Open<BigInteger> open) {
		BigInteger secret = open.getSecret();
		BigInteger r = open.getRandomness();
		BigInteger modulus = params.modulus;
		BigInteger order = params.order;
		
		if (!Util.isElementOfZn(secret, order) || !Util.isElementOfZn(r, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger expected = params.g.modPow(secret, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus);
		return (commitment.equals(expected));
	}

	public static Pedersen<BigInteger> generateCommitment(
			PedersenPublicParams<BigInteger> params, BigInteger secret,
			SecureRandom rand) {
		BigInteger order = params.order;
		if (!Util.isElementOfZn(secret, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger modulus = params.modulus;
		BigInteger r = thresholdDSA.Util.randomFromZn(order, rand);
		BigInteger commitment = params.g.modPow(secret, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus);
		Open<BigInteger> open = new Open<BigInteger>(secret, r);
		return new Pedersen<BigInteger>(commitment, open);
	}

}
