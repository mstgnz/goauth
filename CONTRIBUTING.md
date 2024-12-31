# Contributing Guide

Thank you for your interest in contributing to this project! This guide will help you understand the contribution process.

## Development Process

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: amazing feature added'`)
4. Push the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) standard for commit messages:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- feat: A new feature
- fix: A bug fix
- docs: Documentation only changes
- style: Changes that do not affect the meaning of the code (whitespace, formatting, etc.)
- refactor: A code change that neither fixes a bug nor adds a feature
- test: Adding missing tests or correcting existing tests
- chore: Changes to the build process or auxiliary tools

## Pull Request Process

1. Ensure all tests pass before opening a PR
2. Provide a detailed description of the changes in your PR
3. Include screenshots or code examples if applicable
4. Reference any related issues

## Code Standards

- Follow Go coding standards
- Write tests for new features
- Format your code with `go fmt`
- Run `golangci-lint` for linting
- Add godoc format documentation for functions and types

## Adding New Providers

When adding a new OAuth2 provider:

1. Create a new package under the `provider` directory
2. Implement the base provider interface
3. Define required endpoints and scopes
4. Add test file
5. Add provider to README.md
6. Add example usage code

## Testing

When adding new code:

1. Add unit tests
2. Maintain test coverage above 80%
3. Use mocks appropriately
4. Test edge cases

## Documentation

- Add godoc format documentation for all public APIs
- Add comments for complex logic
- Keep README.md up to date
- Keep example code up to date

## Help and Communication

- Open an issue for questions
- Use the discussions section
- Request reviews on Pull Requests

## License

Your contributions will be licensed under the project's MIT License. 