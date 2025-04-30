import { OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE } from '../../constants/index.js';
/**
 * Builder class for AuthorizationDetails
 */
export class AuthzDetailsBuilder {
    type;
    format;
    types = [];
    locations = [];
    actions = [];
    datatypes = [];
    identifier;
    privileges = [];
    constructor(type, format) {
        this.type = type;
        this.format = format;
    }
    /**
     * Generate a builder with the required parameters to build
     * an instance of AuthorizationDetails valid for the issuance of W3C VC
     * @param format W3C VC format
     * @returns Instance of AuthzDetailsBuilder
     */
    static openIdCredentialBuilder(format) {
        return new AuthzDetailsBuilder(OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE, format);
    }
    /**
     * Set the attribute "types" of a authorization details object
     * @param types Types of the requested credentials
     * @returns This object
     */
    withTypes(types) {
        this.types = types;
        return this;
    }
    /**
     * Set the attribute "locations" of a authorization details object
     * @param locations Locations to include
     * @returns This object
     */
    withLocations(locations) {
        this.locations = locations;
        return this;
    }
    /**
     * Set the attribute "actions" of a authorization details object
     * @param actions Actions to include
     * @returns This object
     */
    withActions(actions) {
        this.actions = actions;
        return this;
    }
    /**
     * Set the attribute "datatypes" of a authorization details object
     * @param datatypes Datatypes of the requested credentials
     * @returns This object
     */
    withDatatypes(datatypes) {
        this.datatypes = datatypes;
        return this;
    }
    /**
     * Set the attribute "identifier" of a authorization details object
     * @param datatypes Identifier of the requested credentials
     * @returns This object
     */
    withIdentifier(identifier) {
        this.identifier = identifier;
        return this;
    }
    /**
     * Set the attribute "privileges" of a authorization details object
     * @param datatypes Privileges of the requested credentials
     * @returns This object
     */
    withPrivileges(privileges) {
        this.privileges = privileges;
        return this;
    }
    /**
     * Generate AuthorizationDetails from the data contained in the builder
     * @returns AuthorizationDetails instance
     */
    build() {
        return {
            type: this.type,
            format: this.format,
            types: this.types,
            locations: this.locations,
            actions: this.actions,
            datatypes: this.datatypes,
            identifier: this.identifier,
            privileges: this.privileges,
        };
    }
}
//# sourceMappingURL=authz_details.builder.js.map