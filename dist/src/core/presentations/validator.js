import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import fetch from 'node-fetch';
async function loadSchema(uri) {
    const response = await fetch(uri);
    if (!response.ok) {
        throw new Error(`
      An error was received when fetchin remote schema: ${response.statusText}`);
    }
    return (await response.json());
}
export const ajv = new Ajv2020({ loadSchema: loadSchema });
addFormats(ajv);
//# sourceMappingURL=validator.js.map