import { pathsToModuleNameMapper } from 'ts-jest';
import { compilerOptions } from './tsconfig.json';
const jestConfig = {
    preset: 'ts-jest/presets/default-esm',
    // setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
    testPathIgnorePatterns: ['/node_modules/', '/dist/'],
    extensionsToTreatAsEsm: ['.ts'],
    testTimeout: 500000, // Set to a higher value for debug
    transform: {
        '^.+\\.spec\\.ts$': ['ts-jest', {
                tsconfig: 'tsconfig.test.json',
                useESM: true
            }],
    },
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.[jt]s$': '$1',
        ...pathsToModuleNameMapper(compilerOptions.paths, {
            // prefix: `<rootDir>/${compilerOptions.baseUrl}/`,
            prefix: '<rootDir>/',
            useESM: true,
        }),
    },
};
export default jestConfig;
//# sourceMappingURL=jest.config.js.map