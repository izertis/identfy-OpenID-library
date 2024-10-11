import { InternalError } from "../../common/classes/index.js";
import { W3CDataModel } from "../../common/formats/index.js";
import { expressDateInSeconds } from "../../common/utils/time.js";
/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export class VcFormatter {
    constructor(dataModel) {
        this.dataModel = dataModel;
    }
    /**
     * Generates a formatter instance based on the specified format
     * @param format The format to consider
     * @param dataModel The W3C data model version
     * @returns A VcFormatter that allow to express unsigned VC in the specified format
     */
    static fromVcFormat(format, dataModel) {
        if (format === "jwt_vc" || format === "jwt_vc_json") {
            return new JwtVcFormatter(dataModel);
        }
        else if (format === "jwt_vc_json-ld" || format === "ldp_vc") {
            throw new InternalError("Unimplemented");
        }
        else {
            throw new InternalError("Unsupported format");
        }
    }
    /**
     * Generates a format that allow to express VC in JWT format
     * @returns A VcFormatter
     */
    static jwtFormatter(dataModel) {
        return new JwtVcFormatter(dataModel);
    }
}
class JwtVcFormatter extends VcFormatter {
    formatVc(vc) {
        const token = {
            sub: vc.credentialSubject.id,
            iss: vc.issuer,
            vc
        };
        if (vc.id) {
            token.jti = vc.id;
        }
        if (this.dataModel === W3CDataModel.V1) {
            return this.formatDataModel1(token, vc);
        }
        else {
            return this.formatDataModel2(token, vc);
        }
    }
    formatDataModel1(token, vc) {
        var _a, _b, _c, _d;
        const nbf = (_a = vc.validFrom) !== null && _a !== void 0 ? _a : ((_b = vc.issuanceDate) !== null && _b !== void 0 ? _b : vc.issued);
        const iat = (_c = vc.issuanceDate) !== null && _c !== void 0 ? _c : ((_d = vc.issued) !== null && _d !== void 0 ? _d : vc.validFrom);
        if (nbf) {
            token.nbf = expressDateInSeconds(nbf);
        }
        if (iat) {
            token.iat = expressDateInSeconds(iat);
        }
        if (vc.expirationDate) {
            token.exp = expressDateInSeconds(vc.expirationDate);
        }
        return token;
    }
    formatDataModel2(token, vc) {
        if (vc.validFrom) {
            token.iat = expressDateInSeconds(vc.validFrom);
            token.nbf = expressDateInSeconds(vc.validFrom);
        }
        if (vc.validUntil) {
            token.exp = expressDateInSeconds(vc.validUntil);
        }
        return token;
    }
}
