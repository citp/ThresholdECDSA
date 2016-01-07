package thresholdDSA.sign;

import java.math.BigInteger;

import static PedersenCommitments.Pedersen.generateCommitment;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import paillierp.Paillier;
import paillierp.PaillierThreshold;
import paillierp.PartialDecryption;
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
import PedersenCommitments.Open;
import PedersenCommitments.Pedersen;
import PedersenCommitments.PedersenPublicParams;
import ZeroKnowledgeProofs.PublicParameters;
import ZeroKnowledgeProofs.Zkp_i1;
import ZeroKnowledgeProofs.Zkp_i2;

public class PlayerSigner {

	private Paillier paillierPublicKey;
	private PaillierThreshold pI;
	private BigInteger encryptedDSAKey;
	private SecureRandom rnd = new SecureRandom();
	private BigInteger rhoI;
	private BigInteger randomness1;
	private BigInteger uI;
	private BigInteger vI;
	private BigInteger u;
	private BigInteger v;
	private ECPoint rI;
	private BigInteger wI;
	private BigInteger w;
	private BigInteger r;
	private PartialDecryption wShare;
	private PartialDecryption sigmaShare;
	private BigInteger kI;
	private BigInteger cI;
	private BigInteger randomness2;
	private PedersenPublicParams<BigInteger> pedersenParams;

	PedersenCommitments.Open<BigInteger> openUi;
	PedersenCommitments.Open<BigInteger> openVi;
	PedersenCommitments.Open<ECPoint> openRi;
	PedersenCommitments.Open<BigInteger> openWi;

	private boolean aborted = false;

	PublicParameters params;

	private byte[] message;
	Round1Message[] round1messages;
	Round3Message[] round3messages;

	public PlayerSigner(PublicParameters params,
			PedersenPublicParams<BigInteger> pedersenParams,
			PaillierPrivateThresholdKey paillierKeyShare,
			BigInteger encryptedDSAKey, byte[] message) {
		paillierPublicKey = new Paillier(paillierKeyShare.getPublicKey());
		pI = new PaillierThreshold(paillierKeyShare);
		this.message = message;
		this.params = params;
		this.pedersenParams = pedersenParams;

		this.encryptedDSAKey = encryptedDSAKey;
	}

	public Round1Message round1() {
		rhoI = Util.randomFromZn(BitcoinParams.q, rnd);
		randomness1 = paillierPublicKey.getPublicKey().getRandomModNStar();
		uI = paillierPublicKey.encrypt(rhoI, randomness1);
		PedersenCommitments.Pedersen<BigInteger> pedersenUi = generateCommitment(
				pedersenParams, uI, rnd);
		openUi = pedersenUi.getOpen();
		vI = paillierPublicKey.multiply(encryptedDSAKey, rhoI);

		PedersenCommitments.Pedersen<BigInteger> pedersenVi = generateCommitment(
				pedersenParams, vI, rnd);
		openVi = pedersenVi.getOpen();
		return new Round1Message(pedersenUi.getCommitment(),
				pedersenVi.getCommitment());

	}

	public Round2Message round2(Round1Message... round1Messages) {
		// save round1messages which contain commitments to ui and vi so you
		// can verify them after they're opened during this round.
		this.round1messages = round1Messages;

		Zkp_i1 zkp1 = new Zkp_i1(params, rhoI, rnd, randomness1, vI,
				encryptedDSAKey, uI);

		if (aborted) {
			return null;
		} else {
			return new Round2Message(openUi, openVi, zkp1);
		}

	}

	public Round3Message round3(Round2Message... round2Messages) {
		// check uI and vi commitments. We are assuming that the players
		// messages are
		// presented in the same order for consecutive rounds. Otherwise, the
		// verification
		// will fail.
		for (int i = 0; i < round2Messages.length; i++) {
			if (!Pedersen.checkCommitment(pedersenParams,
					round1messages[i].uiCommitment, round2Messages[i].openUi)) {
				aborted = true;
			}
			if (!Pedersen.checkCommitment(pedersenParams,
					round1messages[i].vICommitment, round2Messages[i].openVi)) {
				aborted = true;
			}
		}

		// verify Everyone else's Zkp_i1
		for (Round2Message message : round2Messages) {
			long startTime = System.nanoTime();

			if (!message.zkp1.verify(params, BitcoinParams.CURVE,
					message.openVi.getSecret(), encryptedDSAKey,
					message.openUi.getSecret())) {
				aborted = true;
			}

		}

		u = uI;
		for (int i = 0; i < round2Messages.length; i++) {
			u = paillierPublicKey.add(u, round2Messages[i].openUi.getSecret());
		}

		v = vI;
		for (int i = 0; i < round2Messages.length; i++) {
			v = paillierPublicKey.add(v, round2Messages[i].openVi.getSecret());
		}

		kI = Util.randomFromZn(BitcoinParams.q, rnd);
		rI = BitcoinParams.G.multiply(kI);
		cI = Util.randomFromZn(BitcoinParams.q.pow(6), rnd);
		randomness2 = paillierPublicKey.getPublicKey().getRandomModNStar();
		BigInteger mask = paillierPublicKey.encrypt(
				BitcoinParams.q.multiply(cI), randomness2);
		wI = paillierPublicKey.add(paillierPublicKey.multiply(u, kI), mask);
		PedersenCommitments.Pedersen<BigInteger> pedersenWi = generateCommitment(
				pedersenParams, wI, rnd);
		openWi = pedersenWi.getOpen();
		BigInteger rICommitment = null;
		openRi = new Open<ECPoint>(rI, null);

		if (aborted) {
			return null;
		} else {
			return new Round3Message(rICommitment, pedersenWi.getCommitment());
		}

	}

	public Round4Message round4(Round3Message... round3Messages) {
		// save round3messages which contain commitments to wi and ri so you
		// can verify them after they're opened during this round.
		this.round3messages = round3Messages;

		Zkp_i2 zkp2 = new Zkp_i2(params, kI, cI, rnd, BitcoinParams.G, wI, u,
				randomness2);

		if (aborted) {
			return null;
		} else {
			return new Round4Message(openRi, openWi, zkp2);
		}

	}

	@SuppressWarnings("deprecation")
	public Round5Message round5(Round4Message... round4Messages) {
		// check uI and vi commitments. We are assuming that the players
		// messages are presented in the same order for consecutive
		// rounds. Otherwise, the verification will fail.
		for (int i = 0; i < round4Messages.length; i++) {
			if (!Pedersen.checkCommitment(pedersenParams,
					round3messages[i].wiCommitment, round4Messages[i].openWi)) {
				aborted = true;
			}
		}

		// verify Everyone else's Zkp_i2
		for (Round4Message message : round4Messages) {
			long startTime = System.nanoTime();

			if (!message.zkp2.verify(params, BitcoinParams.CURVE,
					message.openRi.getSecret(), u, message.openWi.getSecret())) {
				aborted = true;
			}
		}

		w = wI;
		for (int i = 0; i < round4Messages.length; i++) {
			w = paillierPublicKey.add(w, round4Messages[i].openWi.getSecret());
		}

		ECPoint R = rI;
		for (int i = 0; i < round4Messages.length; i++) {
			R = R.add(round4Messages[i].openRi.getSecret());
		}

		r = R.getX().toBigInteger().mod(BitcoinParams.q);
		wShare = pI.decrypt(w);

		if (aborted) {
			return null;
		} else {
			return new Round5Message(wShare);
		}

	}

	public Round6Message round6(Round5Message... round5Messages) {

		PartialDecryption[] wShares = new PartialDecryption[round5Messages.length + 1];
		wShares[0] = wShare;
		for (int i = 0; i < round5Messages.length; i++) {
			wShares[i + 1] = round5Messages[i].wShare;
		}
		BigInteger mu = pI.combineShares(wShares);
		BigInteger sigma = paillierPublicKey.multiply(paillierPublicKey.add(
				paillierPublicKey.multiply(u,
						Util.calculateMPrime(BitcoinParams.q, message)),
				paillierPublicKey.multiply(v, r)), mu
				.modInverse(BitcoinParams.q));

		sigmaShare = pI.decrypt(sigma);

		if (aborted) {
			return null;
		} else {
			return new Round6Message(sigmaShare);
		}
	}

	public DSASignature outputSignature(Round6Message... round6Messages) {
		PartialDecryption[] sigmaShares = new PartialDecryption[round6Messages.length + 1];
		sigmaShares[0] = sigmaShare;
		for (int i = 0; i < round6Messages.length; i++) {
			sigmaShares[i + 1] = round6Messages[i].sigmaShare;
		}
		BigInteger s = pI.combineShares(sigmaShares).mod(BitcoinParams.q);

		if (aborted) {
			return null;
		} else {
			return new DSASignature(r, s);
		}
	}

}
