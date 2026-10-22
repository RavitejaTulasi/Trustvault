module.exports = {
  testEnvironment: 'jsdom',
  moduleNameMapper: {
    '\\.(css|scss|sass)$': '<rootDir>/__mocks__/styleMock.js',
  },
};