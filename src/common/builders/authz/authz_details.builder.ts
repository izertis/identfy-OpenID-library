import {OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE} from '../../constants/index.js';
import {W3CVerifiableCredentialFormats} from '../../formats/index.js';
import {AuthorizationDetails} from '../../interfaces/authz_details.interface.js';

/**
 * Builder class for AuthorizationDetails
 */
export class AuthzDetailsBuilder {
  private types: string[] = [];
  private locations: string[] = [];
  private actions: string[] = [];
  private datatypes: string[] = [];
  private identifier?: string;
  private privileges: string[] = [];

  private constructor(
    private type: string,
    private format: W3CVerifiableCredentialFormats,
  ) {}

  /**
   * Generate a builder with the required parameters to build
   * an instance of AuthorizationDetails valid for the issuance of W3C VC
   * @param format W3C VC format
   * @returns Instance of AuthzDetailsBuilder
   */
  static openIdCredentialBuilder(
    format: W3CVerifiableCredentialFormats,
  ): AuthzDetailsBuilder {
    return new AuthzDetailsBuilder(
      OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
      format,
    );
  }

  /**
   * Set the attribute "types" of a authorization details object
   * @param types Types of the requested credentials
   * @returns This object
   */
  withTypes(types: string[]): AuthzDetailsBuilder {
    this.types = types;
    return this;
  }

  /**
   * Set the attribute "locations" of a authorization details object
   * @param locations Locations to include
   * @returns This object
   */
  withLocations(locations: string[]): AuthzDetailsBuilder {
    this.locations = locations;
    return this;
  }

  /**
   * Set the attribute "actions" of a authorization details object
   * @param actions Actions to include
   * @returns This object
   */
  withActions(actions: string[]): AuthzDetailsBuilder {
    this.actions = actions;
    return this;
  }

  /**
   * Set the attribute "datatypes" of a authorization details object
   * @param datatypes Datatypes of the requested credentials
   * @returns This object
   */
  withDatatypes(datatypes: string[]): AuthzDetailsBuilder {
    this.datatypes = datatypes;
    return this;
  }

  /**
   * Set the attribute "identifier" of a authorization details object
   * @param datatypes Identifier of the requested credentials
   * @returns This object
   */
  withIdentifier(identifier: string): AuthzDetailsBuilder {
    this.identifier = identifier;
    return this;
  }

  /**
   * Set the attribute "privileges" of a authorization details object
   * @param datatypes Privileges of the requested credentials
   * @returns This object
   */
  withPrivileges(privileges: string[]): AuthzDetailsBuilder {
    this.privileges = privileges;
    return this;
  }

  /**
   * Generate AuthorizationDetails from the data contained in the builder
   * @returns AuthorizationDetails instance
   */
  build(): AuthorizationDetails {
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
