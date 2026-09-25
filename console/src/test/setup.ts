import '@testing-library/jest-dom/vitest'

// jsdom does not implement URL.createObjectURL / revokeObjectURL, which the
// report preview uses. Stub them so render smoke tests don't crash; the value
// is never dereferenced in tests.
if (typeof URL.createObjectURL !== 'function') {
  URL.createObjectURL = () => 'blob:stub'
}
if (typeof URL.revokeObjectURL !== 'function') {
  URL.revokeObjectURL = () => undefined
}
