module.exports = {
  extends: ['react-app'],
  env: {
    node: true,
  },
  overrides: [
    {
      files: ['tests/unit/**/*.js'],
      globals: {
        afterAll: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        beforeEach: 'readonly',
        describe: 'readonly',
        expect: 'readonly',
        it: 'readonly',
        test: 'readonly',
        vi: 'readonly',
      },
    },
    {
      files: ['tests/load/**/*.js'],
      globals: {
        __ENV: 'readonly',
      },
      rules: {
        'import/no-anonymous-default-export': 'off',
      },
    },
  ],
};
