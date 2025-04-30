/**
 * Defines in which location the request for authorisation should be included:
 * - PLAIN_REQUEST: The request is not signed and travels in the same HTTP
 * request as in the form of parameters.
 * - JWT_OBJECT: The request is signed and represented as a JWT
 */
export var AuthzRequestLocation;
(function (AuthzRequestLocation) {
    AuthzRequestLocation[AuthzRequestLocation["PLAIN_REQUEST"] = 0] = "PLAIN_REQUEST";
    AuthzRequestLocation[AuthzRequestLocation["JWT_OBJECT"] = 1] = "JWT_OBJECT";
})(AuthzRequestLocation || (AuthzRequestLocation = {}));
//# sourceMappingURL=authz_request.interface.js.map