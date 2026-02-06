# Contributing to SnmpQuery

First off, thank you for considering contributing to SnmpQuery! It's people like you that make this tool better for everyone.

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates.

When filing a bug report, include:
- **Clear title and description**
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details:**
  - OS and version
  - Python version
  - Network device types (Cisco, Ubiquiti, etc.)
  - Relevant configuration (sanitized)
- **Relevant logs** (remember to sanitize sensitive data!)

### 💡 Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:
- **Clear title and description**
- **Use case** - why is this enhancement needed?
- **Proposed solution** - how might it work?
- **Alternatives considered**

### 🧪 Hardware Testing Reports

One of the most valuable contributions is testing SnmpQuery on different network hardware!

**Tested and working:**
- ✅ Cisco ISR 4000, 1900, 2800 series routers
- ✅ Various L2 managed switches with SNMP support

**Need testing:**
- ⚠️ Ubiquiti UniFi devices
- ⚠️ MikroTik routers
- ⚠️ TP-Link Omada ecosystem
- ⚠️ Juniper devices
- ⚠️ HP/Aruba switches

If you test on new hardware, please open an issue with:
- Hardware model and firmware version
- What works / what doesn't
- Any special configuration needed
- SNMP MIB specifics if relevant

### 🔧 Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes**
3. **Test thoroughly** - ensure existing functionality still works
4. **Update documentation** if needed
5. **Follow the existing code style**
6. **Submit a pull request** with a clear description

#### Code Style Guidelines

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Include docstrings for functions
- Keep functions focused (single responsibility)

#### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests liberally

Example:
```
Add support for Ubiquiti switches

- Implement UniFi-specific OID mappings
- Add detection for UniFi switch models
- Update documentation with UniFi configuration

Fixes #123
```

### 📝 Documentation

Improvements to documentation are always welcome! This includes:
- README updates
- Code comments
- Configuration examples
- Troubleshooting guides
- Wiki pages

### 🌍 Translations

Currently, SnmpQuery is English-only. If you'd like to add internationalization support or translate to other languages, please open an issue to discuss the approach first.

## Development Setup

1. **Fork and clone:**
   ```bash
   git clone https://github.com/YOUR-USERNAME/snmpquery.git
   cd snmpquery
   ```

2. **Set up Python environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Install system dependencies:**
   ```bash
   sudo apt install snmp nbtscan pmacct  # Ubuntu/Debian
   ```

4. **Create test configuration:**
   ```bash
   cp snmpQuery.ini.example snmpQuery.ini
   # Edit with your test network details
   ```

5. **Set up test database:**
   ```bash
   mkdir -p /ramdisk  # May need sudo
   # Or use a regular directory for testing
   ```

## Testing

Before submitting a PR:

1. **Manual testing:**
   - Start snmpPyServer.py and verify it discovers devices
   - Test the web interface queries
   - If touching NetFlow code, test with flow data

2. **Check for errors:**
   - Watch for Python exceptions
   - Check log files
   - Verify database integrity

3. **Test edge cases:**
   - Empty results
   - Invalid input
   - Network timeouts
   - Missing configuration

## Project Structure

```
snmpquery/
├── snmpPyServer.py         # Main daemon - SNMP queries and device discovery
├── funciones.py            # Core utility functions and queries
├── netflowProcessor.py     # NetFlow traffic categorization
├── nfacctd-collector.py    # NetFlow data collection
├── flask_web_server.py     # Web interface
├── services.py             # Service identification database
├── nfacctd.conf           # NetFlow collector configuration
├── requirements.txt        # Python dependencies
├── snmpQuery.ini.example  # Configuration template
└── README.md              # Main documentation
```

## Questions?

Don't hesitate to ask questions by:
- Opening an issue with the "question" label
- Starting a discussion in GitHub Discussions

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and professional in all interactions.

### Expected Behavior

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal or political attacks
- Public or private harassment
- Publishing others' private information without permission
- Trolling or insulting/derogatory comments

## License

By contributing to SnmpQuery, you agree that your contributions will be licensed under the GNU Affero General Public License v3.0 (AGPLv3).

This means:
- Your code will remain open source
- Others can use and modify it freely
- Network/SaaS deployments must provide source code
- All derivative works must also be AGPLv3

## Recognition

Contributors will be recognized in:
- GitHub contributors list (automatic)
- Release notes for significant contributions
- README acknowledgments section (for major contributions)

---

Thank you for helping make SnmpQuery better! 🎉
