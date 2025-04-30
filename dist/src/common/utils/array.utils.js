export function arraysAreEqual(arr1, arr2) {
    return (Array.isArray(arr1) &&
        Array.isArray(arr2) &&
        arr1.length === arr2.length &&
        arr1.every((val, index) => val === arr2[index]));
}
//# sourceMappingURL=array.utils.js.map