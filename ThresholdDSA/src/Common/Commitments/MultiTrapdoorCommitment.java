package Common.Commitments;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import ACNS.thresholdDSA.Util;
import uk.ac.ic.doc.jpair.api.Field;
import uk.ac.ic.doc.jpair.api.FieldElement;
import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.pairing.BigInt;
import uk.ac.ic.doc.jpair.pairing.EllipticCurve;
import uk.ac.ic.doc.jpair.pairing.Point;
import uk.ac.ic.doc.jpair.pairing.Predefined;

public class MultiTrapdoorCommitment {

	private final Commitment commitment;
	private final Open<BigInteger> open;

	private MultiTrapdoorCommitment(Commitment commitment, Open<BigInteger> open) {
		this.commitment = commitment;
		this.open = open;

	}
	
	public Open<BigInteger> getOpen(){
		return open;
	}
	
	public Commitment getCommitment() {
		return commitment;
	}

	public static MultiTrapdoorCommitment multilinnearCommit(Random rand,
			MultiTrapdoorMasterPublicKey mpk, BigInteger... secrets) {
		EllipticCurve curve = mpk.pairing.getCurve();
		BigInteger e = Util.randomFromZn(mpk.q, rand);
		BigInteger r = Util.randomFromZn(mpk.q, rand);
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		BigInteger digest = new BigInteger(Util.sha256Hash(secretsBytes))
				.mod(mpk.q); // AR mod
		Point he = curve.add(mpk.h, curve.multiply(mpk.g, new BigInt(e)));
		Point a = curve.add(curve.multiply(mpk.g, new BigInt(digest)), curve.multiply(he, new BigInt(r)));
		Open<BigInteger> open = new Open<BigInteger>(r, secrets);
		Commitment commitment = new Commitment(e, a);
		
		return new MultiTrapdoorCommitment(commitment, open);
		
	}
	
	
	
	public static MultiTrapdoorCommitment multilinnearCommit(Random rand,
			MultiTrapdoorMasterPublicKey mpk, byte[]... secrets) {
		BigInteger[] secretsBigInt = new BigInteger[secrets.length];
		for(int i = 0; i < secrets.length;i++) {
			secretsBigInt[i] = new BigInteger(secrets[i]);
		}
		return multilinnearCommit(rand, mpk, secrets);
	}

	public static boolean checkcommitment(Commitment commitment,
	Open<BigInteger> open, MultiTrapdoorMasterPublicKey mpk) {
		
		EllipticCurve curve = mpk.pairing.getCurve();
		Point g = mpk.g;
		Point h = mpk.h;
		BigInteger[] secrets = open.getSecrets();
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		BigInteger digest = new BigInteger(Util.sha256Hash(secretsBytes))
				.mod(mpk.q); // AR mod
		return DDHTest(curve.multiply(g,new BigInt(open.getRandomness())),
				curve.add(h, curve.multiply(g, new BigInt(commitment.pubkey))),
				curve.add(commitment.committment, curve.multiply(g, new BigInt(digest.negate()))), g,
				mpk.pairing);

	}

	static boolean DDHTest(Point a, Point b, Point c, Point generator,
			Pairing pairing) {
		EllipticCurve curve = pairing.getCurve();
		return pairing.compute(a, b).equals(pairing.compute(generator, c));


	}

	public static MultiTrapdoorMasterPublicKey generateNMMasterPublicKey() {
		
		//using a predefined pairing
		Pairing pairing = Predefined.ssTate();

		//get P, which is a random point in group G1
		Random rnd = new SecureRandom();
		
		EllipticCurve G = pairing.getCurve();
		Point g = G.getBasePoint(rnd, pairing.getGroupOrder(), pairing.getCofactor());
		BigInteger q = new BigInteger(pairing.getGroupOrder().toByteArray());
		Point h = pairing.RandomPointInG1(rnd);
		//		int rBits = 160;
//		int qBits = 512;
//		PairingParametersGenerator pg = new TypeA1CurveGenerator(2, 512);
//		PairingParameters params = pg.generate();
//		PairingFactory.getInstance().setUsePBCWhenPossible(true);
//		Pairing pairing = PairingFactory.getPairing(params);
//
//		// pairing is symmetric so G =G1 = G2
//		Field G = pairing.getG1();
//		BigInteger q = G.getOrder();
//		Element g = G.newRandomElement(); // check not infinity -- any other
//		Element h = g.pow((Util.randomFromZn(q, new SecureRandom())));

		// element generates since it's

		// prime order
//		Point a = G.multiply(g, BigInt.valueOf(25)); 
//		Point b = G.multiply(g, BigInt.valueOf(4)); 
//		Point c = G.multiply(g, BigInt.valueOf(100)); 
//		System.err.println(pairing.compute(a, b));
//		System.err.println(pairing.compute(c, g));
//
//
//		System.out.println(DDHTest(a, b, c, g, pairing));
	return new MultiTrapdoorMasterPublicKey(g, q, h, pairing);

	}

	public static void main(String[] args) {


		MultiTrapdoorMasterPublicKey mpk = generateNMMasterPublicKey();

		BigInteger msg = BigInteger.valueOf(3445357);

		MultiTrapdoorCommitment c = multilinnearCommit(new SecureRandom(), mpk,

		msg);
		System.out.println(checkcommitment(c.commitment, c.open, mpk));

	}

}