const { defineConfig } = require('vitest/config');

module.exports = defineConfig({
  test: {
    environment: 'node',
    globals: true,
    clearMocks: true,
    include: ['tests/unit/**/*.test.js', 'tests/integration/**/*.test.js'],
    coverage: {
      include: ['server/**/*.js', 'functions/**/*.cjs'],
      exclude: ['server/index.js'],
    },
  },
});
