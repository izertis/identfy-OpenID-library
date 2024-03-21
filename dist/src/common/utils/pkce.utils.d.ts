/***
 * Generate a pkce challenge that resolve with the code_verifier provided
 * @param code_verifier The code verifier that will resolve the challenge. If not
 * provided, code_verifier will be a random generated string of seven characters
 */
export declare function generateChallenge(code_verifier?: string): Promise<string>;
