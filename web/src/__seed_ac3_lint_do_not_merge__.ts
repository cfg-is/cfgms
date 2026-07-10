// SEED: AC3 lint-gate demonstration. Delete before merge.
// Triggers no-eval:error (eslint.config.js:66) and security/detect-eval-with-expression.
// Used to capture a failing frontend-checks run URL for the PR description.
const x = eval('window.location.href')
export { x }
