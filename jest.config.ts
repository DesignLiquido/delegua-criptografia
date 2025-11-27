import type { Config } from '@jest/types';

export default async (): Promise<Config.InitialOptions> => {
    return {
        verbose: true,
        coverageReporters: ['json-summary', 'lcov', 'text', 'text-summary'],
        modulePathIgnorePatterns: ["<rootDir>/dist/"],
        preset: 'ts-jest',
        testEnvironment: 'node',
        roots: ['<rootDir>/fontes', '<rootDir>/testes'],
        transform: {
            '^.+\\.ts$': [
                'ts-jest',
                {
                    tsconfig: {
                        esModuleInterop: true,
                        allowSyntheticDefaultImports: true
                    }
                }
            ]
        },
        collectCoverageFrom: [
            'fontes/**/*.ts',
            '!testes/**/*.ts'
        ],
        coverageDirectory: 'coverage',
        moduleFileExtensions: ['ts', 'js', 'json']
    };
};