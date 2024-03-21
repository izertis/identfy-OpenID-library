var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { generateChallenge as pkceGenerate } from "pkce-challenge";
import { generateRandomString } from "./string.utils.js";
import { DEFAULT_PKCE_LENGTH } from "../constants/index.js";
/***
 * Generate a pkce challenge that resolve with the code_verifier provided
 * @param code_verifier The code verifier that will resolve the challenge. If not
 * provided, code_verifier will be a random generated string of seven characters
 */
export function generateChallenge(code_verifier) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!code_verifier) {
            code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH);
        }
        return yield pkceGenerate(code_verifier);
    });
}
