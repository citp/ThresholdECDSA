/* Licensed under the Apache License, Version 2.0 (the "License");
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
package l2fheBased.thresholdDSA.sign;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import l2fheBased.thresholdDSA.data.BitcoinParams;
import l2fheBased.thresholdDSA.data.Round1Message;
import l2fheBased.thresholdDSA.data.Round2Message;
import l2fheBased.thresholdDSA.data.Round3Message;
import l2fheBased.thresholdDSA.data.Round4Message;

import org.bouncycastle.math.ec.ECPoint;

import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.l2fhe.L1Ciphertext;
import paillierp.l2fhe.L2Ciphertext;
import paillierp.l2fhe.L2FHE;
import paillierp.l2fhe.L2PartialDecryption;
import paillierp.l2fhe.ThresholdL2FHE;
import ACNS.ZeroKnowledgeProofs.PublicParameters;
import ACNS.thresholdDSA.Util;
import l2fheBased.ZeroKnowledgeProofs.Zkp;
import l2fheBased.thresholdDSA.data.DSASignature;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;
import Common.Commitments.Open;

public class PlayerSigner {

	private L2FHE paillierPublicKey;
	private ThresholdL2FHE pI;
	private L1Ciphertext encryptedDSAKey;
	private SecureRandom rnd = new SecureRandom();
	private BigInteger rhoI;
	private BigInteger randomness1;
	private BigInteger randomness2;
	private BigInteger randomness3;

	private L1Ciphertext myUI;
	private L1Ciphertext myVI;
	private L1Ciphertext myWI;
	private L1Ciphertext u;
	private L1Ciphertext v;
	private L1Ciphertext w;
	private ECPoint myRI;
	private BigInteger r;
	private BigInteger cI;
	private L2PartialDecryption sigmaShare;
	private BigInteger kI;

	private boolean aborted = false;

	PublicParameters params;

	private byte[] message;
	Round1Message[] round1messages;
	Round3Message[] round3messages;
	MultiTrapdoorMasterPublicKey nmmpk;
	private Open<BigInteger> myOpenRiUiViWi;
	private L2PartialDecryption etaShare;

	public PlayerSigner(PublicParameters params,
			MultiTrapdoorMasterPublicKey nmmpk,
			PaillierPrivateThresholdKey paillierKeyShare,
			L1Ciphertext encryptedDSAKey, byte[] message) {
		paillierPublicKey = new L2FHE(paillierKeyShare.getPublicKey());
		pI = new ThresholdL2FHE(paillierKeyShare);
		this.message = message;
		this.params = params;
		this.nmmpk = nmmpk;

		this.encryptedDSAKey = encryptedDSAKey;
	}

	public Round1Message round1() {
		rhoI = Util.randomFromZn(BitcoinParams.q, rnd);
		kI = Util.randomFromZn(BitcoinParams.q, rnd);
		cI = Util.randomFromZn(BitcoinParams.q.pow(6), rnd);
		myRI = BitcoinParams.G.multiply(kI);

		randomness1 = paillierPublicKey.getPublicKey().getRandomModNStar();
		randomness2 = paillierPublicKey.getPublicKey().getRandomModNStar();
		randomness3 = paillierPublicKey.getPublicKey().getRandomModNStar();
		myUI = paillierPublicKey.encrypt1(rhoI, randomness1);
		myVI = paillierPublicKey.encrypt1(kI, randomness2);
		myWI = paillierPublicKey.encrypt1(cI, randomness3);

		MultiTrapdoorCommitment commRiUiViWi = null;
		// SLOW
		// try {
		// commRiUiViWi = MultiTrapdoorCommitment
		// .multilinnearCommit(rnd, nmmpk,
		// new BigInteger(rI.getEncoded()),
		// new BigInteger(serialize(uI)), new BigInteger(serialize(vI)), new
		// BigInteger(serialize(wI)));
		// } catch (IOException e) {
		// System.out.println("Comittment failed with Error " + e);
		// e.printStackTrace();
		// }
		commRiUiViWi = MultiTrapdoorCommitment.multilinnearCommit(rnd, nmmpk,
				new BigInteger(myRI.getEncoded()), myUI.a, myUI.beta, myVI.a,
				myVI.beta, myWI.a, myWI.beta);

		myOpenRiUiViWi = commRiUiViWi.getOpen();
		return new Round1Message(commRiUiViWi.getCommitment());

	}

	public Round2Message round2(Round1Message... round1Messages) {
		// save round1messages which contain commitments to rI,uI,vI and wI so
		// you
		// can verify them after they're opened during this round.
		this.round1messages = round1Messages;
		// We need to convert the L0 ciphertext into a regular paillier
		// encryption
		// so we can recycle the proof from ggn16
		Zkp zkp = new Zkp(params, kI, rhoI, cI, rnd, BitcoinParams.G, myRI, myVI, myUI, myWI,
				myVI.toPaillierCiphertext(paillierPublicKey.getPublicKey()),
				myUI.toPaillierCiphertext(paillierPublicKey.getPublicKey()),
				myWI.toPaillierCiphertext(paillierPublicKey.getPublicKey()),
				randomness2, randomness1, randomness3);
	
		return new Round2Message(myOpenRiUiViWi, zkp);
	}

	public Round3Message round3(Round2Message... round2Messages) {
		// check commitments. We are assuming that the players
		// messages are
		// presented in the same order for consecutive rounds. Otherwise, the
		// verification
		// will fail.
		ECPoint R = myRI;
		u = myUI;
		v = myVI;
		w = myWI;


		for (int i = 0; i < round2Messages.length; i++) {

			// from player i
			BigInteger[] playerIsSecrets = round2Messages[i].openRiUiViWi
					.getSecrets();
			ECPoint rI = BitcoinParams.CURVE.getCurve().decodePoint(
					playerIsSecrets[0].toByteArray());
			L1Ciphertext uI = new L1Ciphertext(playerIsSecrets[1],
					playerIsSecrets[2]);
			L1Ciphertext vI = new L1Ciphertext(playerIsSecrets[3],
					playerIsSecrets[4]);
			L1Ciphertext wI = new L1Ciphertext(playerIsSecrets[5],
					playerIsSecrets[6]);

			// check commitments
			


			
			if (!MultiTrapdoorCommitment.checkcommitment(
					round1messages[i].riUiViWiCommitment,
					round2Messages[i].openRiUiViWi, nmmpk)) {
				aborted = true;
			}

			// verify ZKPs
			if (!round2Messages[i].zkp.verify(params, BitcoinParams.CURVE, rI,
					vI, uI, wI)) {
				aborted = true;
			}


			R = R.add(rI);
			u = paillierPublicKey.add(u, uI);
			v = paillierPublicKey.add(v, vI);
			w = paillierPublicKey.add(w, wI);

		}
		
	
		L1Ciphertext wq = paillierPublicKey.cMult(w, BitcoinParams.q);
		r = R.getX().toBigInteger().mod(BitcoinParams.q);
		L2Ciphertext uv = paillierPublicKey.mult(u, v);
		L2Ciphertext z = paillierPublicKey.add(wq, uv);
		etaShare = pI.decrypt(z);
		if (aborted) {
			return null;
		} else {
			return new Round3Message(etaShare);
		}

	}

	public Round4Message round4(Round3Message... round3Messages) {

		L2PartialDecryption[] etaShares = new L2PartialDecryption[round3Messages.length + 1];
		etaShares[0] = etaShare;
		for (int i = 0; i < round3Messages.length; i++) {
			L2PartialDecryption share = round3Messages[i].etaShare;
			etaShares[i + 1] = share;
		}
		BigInteger eta = pI.combineShares(etaShares);
		BigInteger psi = eta.modInverse(BitcoinParams.q);
		L1Ciphertext vHat = paillierPublicKey.cMult(u, psi);

		L1Ciphertext encryptedMessage = paillierPublicKey
				.fixedRandomnessEncrypt(Util.calculateMPrime(BitcoinParams.q,
						message));
		L2Ciphertext sigma = paillierPublicKey.mult(
				vHat,
				paillierPublicKey.add(encryptedMessage,
						paillierPublicKey.cMult(encryptedDSAKey, r)));

		sigmaShare = pI.decrypt(sigma);

		if (aborted) {
			return null;
		} else {
			return new Round4Message(sigmaShare);
		}
	}

	public DSASignature outputSignature(Round4Message... round4Messages) {
		L2PartialDecryption[] sigmaShares = new L2PartialDecryption[round4Messages.length + 1];
		sigmaShares[0] = sigmaShare;
		for (int i = 0; i < round4Messages.length; i++) {
			sigmaShares[i + 1] = round4Messages[i].sigmaShare;
		}
		BigInteger s = pI.combineShares(sigmaShares).mod(BitcoinParams.q);

		if (aborted) {
			return null;
		} else {
			return new DSASignature(r, s);
		}
	}

}
