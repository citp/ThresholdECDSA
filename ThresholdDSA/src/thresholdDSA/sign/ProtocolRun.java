package thresholdDSA.sign;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateThresholdKey;
import thresholdDSA.Util;
import thresholdDSA.data.BitcoinParams;
import thresholdDSA.data.DSASignature;
import thresholdDSA.data.Round1Message;
import thresholdDSA.data.Round2Message;
import thresholdDSA.data.Round3Message;
import thresholdDSA.data.Round4Message;
import thresholdDSA.data.Round5Message;
import thresholdDSA.data.Round6Message;
import PedersenCommitments.PedersenPublicParams;
import ZeroKnowledgeProofs.PublicParameters;

public class ProtocolRun {

	public static void main(String[] args) throws ClassNotFoundException, IOException {
		

		SecureRandom rnd = new SecureRandom();

		if (!new File("key_2046_3-15").exists()) {
				System.out.println("generating new key");
				Util.generatePaillierKeyShares("key_2046_3-15", rnd, 15, 3);
		}

		PaillierPrivateThresholdKey[] keys = KeyGen
				.PaillierThresholdKeyLoad("key_2046_3-15");

		Paillier paillierPublicKey = new Paillier(keys[0].getPublicKey());

		PublicParameters params = Util.generateParamsforBitcoin(256, 512, rnd,
				paillierPublicKey.getPublicKey());

		PedersenPublicParams<BigInteger> pedersenPublicParams;
		if (!new File("pedersen-params-4096").exists()) {
			pedersenPublicParams = PedersenCommitments.Util
					.generatePedersenParamsFromInternet("pedersen-params-4096", 
							"thresholdDSA");
		} else {
			pedersenPublicParams = PedersenCommitments.Util.readPedersenParams("pedersen-params-4096");
		}
		
		BigInteger privateKey;
		do {
			privateKey = new BigInteger(256, rnd);
		} while (privateKey.compareTo(BitcoinParams.q) != -1);

		byte[] DSApublicKey = Util.compressPoint(
				BitcoinParams.G.multiply(privateKey), BitcoinParams.CURVE)
				.getEncoded();

		BigInteger encryptedDSAKey = paillierPublicKey.encrypt(privateKey);
		
		byte[] messageToSign = new byte[] { 1, 2, 4, 3 };

		long startTime = System.nanoTime();
		PlayerSigner player1 = new PlayerSigner(params, pedersenPublicParams,
				keys[3], encryptedDSAKey, messageToSign);
		PlayerSigner player2 = new PlayerSigner(params, pedersenPublicParams,
				keys[4], encryptedDSAKey, messageToSign);
		PlayerSigner player3 = new PlayerSigner(params, pedersenPublicParams,
				keys[5], encryptedDSAKey, messageToSign);

		// Round 1

		Round1Message p1r1 = player1.round1();
		Round1Message p2r1 = player2.round1();
		Round1Message p3r1 = player3.round1();

		// round 2

		Round2Message p1r2 = player1.round2(p2r1, p3r1);
		Round2Message p2r2 = player2.round2(p1r1, p3r1);
		Round2Message p3r2 = player3.round2(p1r1, p2r1);

		// Round 3
		Round3Message p1r3 = player1.round3(p2r2, p3r2);
		Round3Message p2r3 = player2.round3(p1r2, p3r2);
		Round3Message p3r3 = player3.round3(p1r2, p2r2);

		// round 4
		Round4Message p1r4 = player1.round4(p2r3, p3r3);
		Round4Message p2r4 = player2.round4(p1r3, p3r3);
		Round4Message p3r4 = player3.round4(p1r3, p2r3);

		// round 5
		Round5Message p1r5 = player1.round5(p2r4, p3r4);
		Round5Message p2r5 = player2.round5(p1r4, p3r4);
		Round5Message p3r5 = player3.round5(p1r4, p2r4);

		// round 4
		@SuppressWarnings("unused")
		Round6Message p1r6 = player1.round6(p2r5, p3r5);
		Round6Message p2r6 = player2.round6(p1r5, p3r5);
		Round6Message p3r6 = player3.round6(p1r5, p2r5);

		DSASignature sig = player1.outputSignature(p2r6, p3r6);

		System.out.println(Util.verifySignature(messageToSign, sig.r, sig.s,
				DSApublicKey, BitcoinParams.CURVE));

	}

}