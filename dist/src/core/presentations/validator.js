var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import fetch from 'node-fetch';
function loadSchema(uri) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield fetch(uri);
        if (!response.ok) {
            throw new Error(`
      An error was received when fetchin remote schema: ${response.statusText}`);
        }
        return yield response.json();
    });
}
export const ajv = new Ajv2020({ loadSchema: loadSchema });
addFormats(ajv);
