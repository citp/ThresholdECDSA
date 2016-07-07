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
package ACNS.thresholdDSA.sign;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import paillierp.Paillier;
import paillierp.PaillierThreshold;
import paillierp.PartialDecryption;
import paillierp.key.PaillierPrivateThresholdKey;
import ACNS.ZeroKnowledgeProofs.PublicParameters;
import ACNS.ZeroKnowledgeProofs.Zkp_i1;
import ACNS.ZeroKnowledgeProofs.Zkp_i2;
import ACNS.thresholdDSA.Util;
import ACNS.thresholdDSA.data.BitcoinParams;
import ACNS.thresholdDSA.data.DSASignature;
import ACNS.thresholdDSA.data.Round1Message;
import ACNS.thresholdDSA.data.Round2Message;
import ACNS.thresholdDSA.data.Round3Message;
import ACNS.thresholdDSA.data.Round4Message;
import ACNS.thresholdDSA.data.Round5Message;
import ACNS.thresholdDSA.data.Round6Message;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;

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

	Common.Commitments.Open<BigInteger> openUiVi;
	Common.Commitments.Open<BigInteger> openRiWi;

	private boolean aborted = false;
	
	PublicParameters params;

	private byte[] message;
	Round1Message[] round1messages;
	Round3Message[] round3messages;
	MultiTrapdoorMasterPublicKey nmmpk;

	public PlayerSigner(PublicParameters params,
			MultiTrapdoorMasterPublicKey nmmpk,
			PaillierPrivateThresholdKey paillierKeyShare,
			BigInteger encryptedDSAKey, byte[] message) {
		paillierPublicKey = new Paillier(paillierKeyShare.getPublicKey());
		pI = new PaillierThreshold(paillierKeyShare);
		this.message = message;
		this.params = params;
		this.nmmpk = nmmpk;

		this.encryptedDSAKey = encryptedDSAKey;
	}

	public Round1Message round1() {
		rhoI = Util.randomFromZn(BitcoinParams.q, rnd);
		randomness1 = paillierPublicKey.getPublicKey().getRandomModNStar();
		uI = paillierPublicKey.encrypt(rhoI, randomness1);
		vI = paillierPublicKey.multiply(encryptedDSAKey, rhoI);

		MultiTrapdoorCommitment commUiVi = MultiTrapdoorCommitment.multilinnearCommit(rnd, nmmpk, uI, vI);
		openUiVi = commUiVi.getOpen();
		return new Round1Message(commUiVi.getCommitment());

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
			return new Round2Message(openUiVi, zkp1);
		}

	}

	public Round3Message round3(Round2Message... round2Messages) {
		// check uI and vi commitments. We are assuming that the players
		// messages are
		// presented in the same order for consecutive rounds. Otherwise, the
		// verification
		// will fail.
				
		for (int i = 0; i < round2Messages.length; i++) {
			if (!MultiTrapdoorCommitment.checkcommitment(
					round1messages[i].uIviCommitment,
					round2Messages[i].openUiVi,nmmpk)) { 
				aborted = true;
			}
		}
		
		

		// verify Everyone else's Zkp_i1
		for (Round2Message message : round2Messages) {
			if (!message.zkp1.verify(params, BitcoinParams.CURVE,
					message.openUiVi.getSecrets()[1], encryptedDSAKey,
					message.openUiVi.getSecrets()[0])) {
				aborted = true;
			}

		}

		u = uI;
		for (int i = 0; i < round2Messages.length; i++) {
			u = paillierPublicKey.add(u,
					round2Messages[i].openUiVi.getSecrets()[0]);
		}

		v = vI;
		for (int i = 0; i < round2Messages.length; i++) {
			v = paillierPublicKey.add(v,
					round2Messages[i].openUiVi.getSecrets()[1]);
		}
				

		kI = Util.randomFromZn(BitcoinParams.q, rnd);
		rI = BitcoinParams.G.multiply(kI);
		cI = Util.randomFromZn(BitcoinParams.q.pow(6), rnd);
		randomness2 = paillierPublicKey.getPublicKey().getRandomModNStar();
		BigInteger mask = paillierPublicKey.encrypt(
				BitcoinParams.q.multiply(cI), randomness2);
		wI = paillierPublicKey.add(paillierPublicKey.multiply(u, kI), mask);
		MultiTrapdoorCommitment commitRiWi = MultiTrapdoorCommitment.multilinnearCommit(	rnd, nmmpk,new BigInteger(rI.getEncoded()), wI);
		openRiWi = commitRiWi.getOpen();

		if (aborted) {
			return null;
		} else {
			return new Round3Message(commitRiWi.getCommitment());
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
			return new Round4Message(openRiWi, zkp2);
		}

	}

	@SuppressWarnings("deprecation")
	public Round5Message round5(Round4Message... round4Messages) {
		
		// check rI and wI commitments. We are assuming that the players
		// messages are presented in the same order for consecutive
		// rounds. Otherwise, the verification will fail.
		for (int i = 0; i < round4Messages.length; i++) {
			if (!MultiTrapdoorCommitment.checkcommitment(
					round3messages[i].riWiCommitment, round4Messages[i].openRiWi, nmmpk)) {
				aborted = true;
			}
		}

		// verify Everyone else's Zkp_i2
		for (Round4Message message : round4Messages) {
			if (!message.zkp2.verify(
					params,
					BitcoinParams.CURVE,
					BitcoinParams.CURVE.getCurve().decodePoint(
							message.openRiWi.getSecrets()[0].toByteArray()), u,
					message.openRiWi.getSecrets()[1])) {
				aborted = true;
			}
		}

		w = wI;
		for (int i = 0; i < round4Messages.length; i++) {
			w = paillierPublicKey.add(w,
					round4Messages[i].openRiWi.getSecrets()[1]);
		}

		ECPoint R = rI;
		for (int i = 0; i < round4Messages.length; i++) {
			R = R.add(BitcoinParams.CURVE.getCurve().decodePoint(
					round4Messages[i].openRiWi.getSecrets()[0].toByteArray()) );
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
			PartialDecryption share = round5Messages[i].wShare;

			wShares[i + 1] = share;
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
