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
package paillierp.l2fhe;

import java.io.Serializable;
import java.math.BigInteger;

import paillierp.key.PaillierKey;
import com.squareup.jnagmp.Gmp;

public class L1Ciphertext implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public final BigInteger a;
	public final BigInteger beta;

	public L1Ciphertext(BigInteger a, BigInteger beta) {
		this.a = a;
		this.beta = beta;
	}
	
	public BigInteger toPaillierCiphertext(PaillierKey pubKey) {
		BigInteger nSquared = pubKey.getNSPlusOne();
		return beta.multiply(Gmp.modPowInsecure(pubKey.getNPlusOne(),a,nSquared)).mod(nSquared);

	}

}
