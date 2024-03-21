import { DidDocumentError } from "../classes/index.js";
import { DIDDocument } from "did-resolver";
import { JWK } from "jose";

/**
 * Obtains the Authentification JWK from a DID Document
 * @param didDocument The DID document from which to extract the key
 * @param methodIdentifier The verification method to search in the DID document
 * @returns The publick key associated in JWK format
 * @throws If the method identifier provided is not specified in a 
 * authentification relationship or if there is not verification method 
 * with that ID. It can also throws if the method does not provide any JWK
 */
export function getAuthentificationJWKKeys(
  didDocument: DIDDocument,
  methodIdentifier: string,
): JWK {
  if (!didDocument.authentication?.includes(methodIdentifier)) {
    throw new DidDocumentError("The kid specified is not the identifier of an authentification relationship");
  }
  if (!didDocument.verificationMethod) {
    throw new DidDocumentError(`No verification methods defined in DidDocumet for did ${didDocument.id}`);
  }
  const verificationMethod = didDocument.verificationMethod.find((method) => method.id === methodIdentifier);
  if (!verificationMethod) {
    throw new DidDocumentError(`There is no verification method with id ${methodIdentifier}`);
  }
  if (!verificationMethod.publicKeyJwk) {
    throw new DidDocumentError("The verificationMethod must contain public key with JWK format");
  }
  return verificationMethod.publicKeyJwk;
}
