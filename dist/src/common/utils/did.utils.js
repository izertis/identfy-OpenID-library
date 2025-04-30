export function didFromDidUrl(didUrl) {
    return didUrl.split('?')[0];
}
export function areDidUrlsSameDid(didUrl1, didUrl2) {
    return didFromDidUrl(didUrl1) === didFromDidUrl(didUrl2);
}
//# sourceMappingURL=did.utils.js.map