# Contributing to cloud-audit-agent

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

1. Fork and clone the repository:

```bash
git clone https://github.com/<your-username>/cloud-audit-agent.git
cd cloud-audit-agent
```

2. Install dependencies:

```bash
npm install
```

3. Run the tests to verify everything works:

```bash
npm test
```

No AWS credentials are needed to run tests — all tests use mocked AWS API responses.

## Making Changes

1. Create a branch for your work:

```bash
git checkout -b feat/my-change
```

2. Make your changes and add tests.

3. Run the test suite:

```bash
npm test
```

4. Submit a pull request against `main`.

## Adding a New AWS Tool

If you're adding a new audit tool:

- **One tool per PR** — this makes review faster and keeps changes focused.
- Add the tool to the appropriate server file in `src/tools/` (or create a new server if it's a new AWS service).
- Always set tool annotations: `readOnlyHint: true, destructiveHint: false, openWorldHint: false`.
- Add unit tests using `aws-sdk-client-mock` — see existing tests in `tests/unit/` for examples.
- Update the tool count in the README if applicable.

## Writing Tests

- Tests use [vitest](https://vitest.dev/) and [aws-sdk-client-mock](https://github.com/m-radzikowski/aws-sdk-client-mock).
- Test **external behavior** (what a tool returns given mocked AWS responses), not implementation details.
- Look at existing test files in `tests/unit/` as reference.

## Code Style

- TypeScript strict mode is enabled.
- Use [Effect-TS](https://effect.website/) for AWS SDK calls via the `awsCall()` wrapper in `src/aws/effect.ts`.
- Use [Zod](https://zod.dev/) for tool input schemas.

## Reporting Issues

Open an issue on GitHub. Include:

- What you were trying to do
- What happened instead
- Steps to reproduce (if applicable)
- Your Node.js version and OS
