import { W3CVerifiableCredentialFormats } from "../../formats/index.js";
import { AuthorizationDetails } from "../../interfaces/authz_details.interface.js";
/**
 * Builder class for AuthorizationDetails
 */
export declare class AuthzDetailsBuilder {
    private type;
    private format;
    private types;
    private locations;
    private actions;
    private datatypes;
    private identifier?;
    private privileges;
    private constructor();
    /**
     * Generate a builder with the required parameters to build
     * an instance of AuthorizationDetails valid for the issuance of W3C VC
     * @param format W3C VC format
     * @returns Instance of AuthzDetailsBuilder
     */
    static openIdCredentialBuilder(format: W3CVerifiableCredentialFormats): AuthzDetailsBuilder;
    /**
     * Set the attribute "types" of a authorization details object
     * @param types Types of the requested credentials
     * @returns This object
     */
    withTypes(types: string[]): AuthzDetailsBuilder;
    /**
     * Set the attribute "locations" of a authorization details object
     * @param locations Locations to include
     * @returns This object
     */
    withLocations(locations: string[]): AuthzDetailsBuilder;
    /**
     * Set the attribute "actions" of a authorization details object
     * @param actions Actions to include
     * @returns This object
     */
    withActions(actions: string[]): AuthzDetailsBuilder;
    /**
     * Set the attribute "datatypes" of a authorization details object
     * @param datatypes Datatypes of the requested credentials
     * @returns This object
     */
    withDatatypes(datatypes: string[]): AuthzDetailsBuilder;
    /**
     * Set the attribute "identifier" of a authorization details object
     * @param datatypes Identifier of the requested credentials
     * @returns This object
     */
    withIdentifier(identifier: string): AuthzDetailsBuilder;
    /**
     * Set the attribute "privileges" of a authorization details object
     * @param datatypes Privileges of the requested credentials
     * @returns This object
     */
    withPrivileges(privileges: string[]): AuthzDetailsBuilder;
    /**
     * Generate AuthorizationDetails from the data contained in the builder
     * @returns AuthorizationDetails instance
     */
    build(): AuthorizationDetails;
}
