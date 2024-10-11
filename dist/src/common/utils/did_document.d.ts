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
export declare function getAuthentificationJWKKeys(didDocument: DIDDocument, methodIdentifier: string): JWK;
/**
 * Obtains the Assertion JWK from a DID Document
 * @param didDocument The DID document from which to extract the key
 * @param methodIdentifier The verification method to search in the DID document
 * @returns The publick key associated in JWK format
 * @throws If the method identifier provided is not specified in a
 * authentification relationship or if there is not verification method
 * with that ID. It can also throws if the method does not provide any JWK
 */
export declare function getAssertionMethodJWKKeys(didDocument: DIDDocument, methodIdentifier: string): JWK;
