import { DidDocumentError } from '../classes/index.js';
// TODO: In a DID Document the VerificationMethod can be expressed
// in differents formats other than JWK.
// https://www.w3.org/TR/did-core/#verification-material
/**
 * Obtains the Authentification JWK from a DID Document
 * @param didDocument The DID document from which to extract the key
 * @param methodIdentifier The verification method to search in the DID document
 * @returns The publick key associated in JWK format
 * @throws If the method identifier provided is not specified in a
 * authentification relationship or if there is not verification method
 * with that ID. It can also throws if the method does not provide any JWK
 */
export function getAuthentificationJWKKeys(didDocument, methodIdentifier) {
    if (!didDocument.authentication?.includes(methodIdentifier)) {
        throw new DidDocumentError('The kid specified is not the identifier of an authentification relationship');
    }
    return getJwkFromDocument(didDocument, methodIdentifier);
}
/**
 * Obtains the Assertion JWK from a DID Document
 * @param didDocument The DID document from which to extract the key
 * @param methodIdentifier The verification method to search in the DID document
 * @returns The publick key associated in JWK format
 * @throws If the method identifier provided is not specified in a
 * authentification relationship or if there is not verification method
 * with that ID. It can also throws if the method does not provide any JWK
 */
export function getAssertionMethodJWKKeys(didDocument, methodIdentifier) {
    if (!didDocument.assertionMethod?.includes(methodIdentifier)) {
        throw new DidDocumentError('The kid specified is not the identifier of an assertionMethod relationship');
    }
    return getJwkFromDocument(didDocument, methodIdentifier);
}
function getJwkFromDocument(didDocument, methodIdentifier) {
    if (!didDocument.verificationMethod) {
        throw new DidDocumentError(`No verification methods defined in DidDocumet for did ${didDocument.id}`);
    }
    const verificationMethod = didDocument.verificationMethod.find(method => method.id === methodIdentifier);
    if (!verificationMethod) {
        throw new DidDocumentError(`There is no verification method with id ${methodIdentifier}`);
    }
    if (!verificationMethod.publicKeyJwk) {
        throw new DidDocumentError('The verificationMethod must contain public key with JWK format');
    }
    return verificationMethod.publicKeyJwk;
}
//# sourceMappingURL=did_document.js.map