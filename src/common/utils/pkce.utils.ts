import {generateChallenge as pkceGenerate} from 'pkce-challenge';
import {generateRandomString} from './string.utils.js';
import {DEFAULT_PKCE_LENGTH} from '../constants/index.js';

/***
 * Generate a pkce challenge that resolve with the code_verifier provided
 * @param code_verifier The code verifier that will resolve the challenge. If not
 * provided, code_verifier will be a random generated string of seven characters
 */
export async function generateChallenge(code_verifier?: string) {
  if (!code_verifier) {
    code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH);
  }
  return await pkceGenerate(code_verifier);
}
