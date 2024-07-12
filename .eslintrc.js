module.exports = {
  root: true,
  extends: ['universe/native', 'prettier'],
  plugins: ['@typescript-eslint', 'prettier'],
  ignorePatterns: ['build'],
  rules: {
    'prettier/prettier': 'error',
  }
};
