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

import paillierp.PartialDecryption;

public class L2PartialDecryption implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public final PartialDecryption a;
	public final PartialDecryption[][] b;
	
	public L2PartialDecryption(PartialDecryption a, PartialDecryption[][] b) {
		this.a = a;
		this.b = b;
	}

}
