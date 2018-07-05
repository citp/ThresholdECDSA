package Common.Commitments;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import ACNS.thresholdDSA.Util;

public class Pedersen<T> {

	private final T commitment;
	private final Open<T> open;

	private Pedersen(T commitment, Open<T> open) {
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
		BigInteger[] secrets = open.getSecrets();
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		BigInteger digest = new BigInteger(Util.sha256Hash(secretsBytes))
				.mod(params.order);
		BigInteger r = open.getRandomness();
		BigInteger modulus = params.modulus;
		BigInteger order = params.order;

		if (!Util.isElementOfZn(digest, order) || !Util.isElementOfZn(r, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger expected = params.g.modPow(digest, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus);
		return (commitment.equals(expected));
	}

	public static Pedersen<BigInteger> generateCommitment(SecureRandom rand,
			PedersenPublicParams<BigInteger> params, BigInteger... secrets) {
		BigInteger order = params.order;
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		BigInteger digest = new BigInteger(Util.sha256Hash(secretsBytes))
				.mod(order); // AR mod
		if (!Util.isElementOfZn(digest, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger modulus = params.modulus;
		BigInteger r = ACNS.thresholdDSA.Util.randomFromZn(order, rand);
		BigInteger commitment = params.g.modPow(digest, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus);
		Open<BigInteger> open = new Open<BigInteger>(r, secrets);
		return new Pedersen<BigInteger>(commitment, open);
	}

	// public static Pedersen<byte[]> generateCommitment(
	// PedersenPublicParams<BigInteger> params, byte[] secret,
	// SecureRandom rand) {
	// BigInteger secretBigInt = new BigInteger(secret);
	// BigInteger order = params.order;
	// if (!Util.isElementOfZn(secretBigInt, order)) {
	// throw new IllegalArgumentException();
	// }
	// BigInteger modulus = params.modulus;
	// BigInteger r = thresholdDSA.Util.randomFromZn(order, rand);
	// byte[] commitment = params.g.modPow(secretBigInt, modulus)
	// .multiply(params.h.modPow(r, modulus)).mod(modulus).toByteArray();
	// Open<byte[]> open = new Open<byte[]>(secret, r.toByteArray());
	// return new Pedersen<byte[]>(commitment, open);
	// }

	/** Simultaneously commit to multiple values */
	public static Pedersen<byte[]> generateCommitment(SecureRandom rand,
			PedersenPublicParams<BigInteger> params, byte[]... secrets) {
		BigInteger order = params.order;
		byte[] digest = Util.sha256Hash(secrets);
		BigInteger digestBigInt = new BigInteger(digest).mod(order);
		if (!Util.isElementOfZn(digestBigInt, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger modulus = params.modulus;
		BigInteger r = ACNS.thresholdDSA.Util.randomFromZn(order, rand);
		byte[] commitment = params.g.modPow(digestBigInt, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus)
				.toByteArray();
		Open<byte[]> open = new Open<byte[]>(r.toByteArray(), secrets);
		return new Pedersen<byte[]>(commitment, open);
	}

	public static boolean checkCommitment(
			PedersenPublicParams<BigInteger> params, byte[] commitment,
			Open<byte[]> open) {
		byte[][] secrets = open.getSecrets();
		byte[] digest = Util.sha256Hash(secrets);
		BigInteger digestBigInt = new BigInteger(digest).mod(params.order); // AR
		BigInteger r = new BigInteger(open.getRandomness());
		BigInteger modulus = params.modulus;
		BigInteger order = params.order;

		if (!Util.isElementOfZn(digestBigInt, order)
				|| !Util.isElementOfZn(r, order)) {
			throw new IllegalArgumentException();
		}
		BigInteger expected = params.g.modPow(digestBigInt, modulus)
				.multiply(params.h.modPow(r, modulus)).mod(modulus);
		return (commitment.equals(expected));
	}


}
