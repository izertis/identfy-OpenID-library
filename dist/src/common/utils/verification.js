/**
 * Utility function that can be used in almost all verification callbacks
 * of the differents components of this library
 * @param _data Any amount of data
 * @returns Allways returns a valid verification
 */
export async function alwaysAcceptVerification(..._data) {
    return { valid: true };
}
//# sourceMappingURL=verification.js.map