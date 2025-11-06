# Contributing to NetGuard Pro

Thank you for your interest in contributing to NetGuard Pro! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/netguard-pro.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Commit your changes: `git commit -m 'Add some feature'`
6. Push to your branch: `git push origin feature/your-feature-name`
7. Submit a pull request

## Development Setup

1. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

2. Install development tools:
   ```bash
   pip3 install flake8 pytest black
   ```

3. Initialize the database:
   ```bash
   python3 NetGuard/scripts/init_database.py
   ```

## Code Style

- Follow PEP 8 Python style guide
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and small
- Comment complex logic

## Testing

Before submitting a pull request:
- Test your changes thoroughly
- Ensure no syntax errors
- Check that existing functionality still works
- Update documentation if needed

## Commit Messages

- Use clear, descriptive commit messages
- Reference issue numbers if applicable
- Format: `type: description`
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `refactor:` for code refactoring
  - `test:` for test additions/changes

## Pull Request Process

1. Ensure your code follows the style guidelines
2. Update documentation if needed
3. Ensure all tests pass (if applicable)
4. Request review from maintainers
5. Address any feedback

## Reporting Issues

When reporting issues, please include:
- Description of the problem
- Steps to reproduce
- Expected behavior
- Actual behavior
- System information (OS, Python version, etc.)
- Relevant logs or error messages

## Security

If you discover a security vulnerability, please email the maintainers directly instead of opening a public issue.

## Questions?

Feel free to open an issue for questions or discussions about the project.

Thank you for contributing to NetGuard Pro!

