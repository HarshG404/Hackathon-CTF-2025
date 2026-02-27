# ICSS India - CTF Web Application

A comprehensive Capture The Flag (CTF) web application designed for web security training. This application appears as a normal educational institute website but contains **34 different security vulnerabilities** for students to discover and exploit.

## 🎯 Overview

This is an enterprise-grade vulnerable web application built with Flask and SQLite. It simulates a real-world educational institute website (ICSS India) with multiple features including:

- User registration and authentication
- Course catalog and enrollment
- Review system
- File upload/download
- Admin panel
- Various utilities and tools

## 🚀 Features

- **34 Unique Vulnerabilities** covering OWASP Top 10 and beyond
- **Independent Exploitation** - Each vulnerability can be exploited without affecting others
- **Flag-based Challenges** - Each successful exploit reveals a unique flag
- **Realistic Interface** - Professional-looking website that appears completely normal
- **Progressive Difficulty** - Beginner to Advanced level challenges
- **Comprehensive Documentation** - Detailed exploitation guide included

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Linux environment (recommended)
- Burp Suite Community Edition (optional but recommended)
- OWASP ZAP (optional)

## 🛠️ Installation

1. **Clone or extract the project**:
   ```bash
   cd icss_ctf
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database**:
   ```bash
   python app.py
   ```
   The database will be created automatically on first run.

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the application**:
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## 🎮 Quick Start for Students

### Default Credentials

**Admin Account**:
- Username: `admin`
- Password: `password123`

**Other Accounts**:
- `instructor` / `instructor@2024`
- `student1` / `student123`
- `testuser` / `test1234`
- `guest` / `guest`

### First Steps

1. Browse the website normally to understand its functionality
2. Check `/robots.txt` for hints
3. View page source and look for HTML comments
4. Try accessing `/api/users`
5. Attempt SQL injection on the login page
6. Use Burp Suite to intercept and modify requests

## 🏆 Vulnerability Categories

The application contains vulnerabilities in the following categories:

- **SQL Injection** (Classic, Blind, Time-based)
- **Cross-Site Scripting** (Reflected, Stored, DOM)
- **Authentication Bypass** (Weak passwords, JWT issues, Session fixation)
- **Authorization** (IDOR, Privilege escalation)
- **File Handling** (Unrestricted upload, LFI, Path traversal)
- **Server Misconfiguration** (Debug mode, Directory listing, Exposed files)
- **Injection Attacks** (Command injection, XXE, SSTI)
- **API Security** (No authentication, CORS misconfiguration)
- **Client-Side** (JS source exposure, HTML comments)
- **CSRF**, **Open Redirect**, **Insecure Deserialization**

## 📚 Documentation

### For Students

Read `CTF_EXPLOITATION_GUIDE.md` for:
- Complete list of all 34 vulnerabilities
- Step-by-step exploitation guides
- Flag locations and capture methods
- Difficulty ratings
- Tools and techniques
- Defense recommendations

### For Instructors

The guide includes:
- Vulnerability descriptions
- Vulnerable code snippets
- Multiple exploitation methods
- Educational objectives
- Scoring suggestions

## 🛡️ Recommended Tools

- **Burp Suite Community Edition** - HTTP proxy and scanner
- **OWASP ZAP** - Automated security testing
- **SQLMap** - SQL injection automation
- **Browser DevTools** - Network analysis and DOM inspection
- **curl** - Command-line HTTP client
- **Postman** - API testing
- **jwt.io** - JWT token decoder
- **CrackStation** - Hash cracker

## 🎓 Learning Objectives

Students will learn to:

1. Identify common web vulnerabilities
2. Use penetration testing tools effectively
3. Exploit vulnerabilities safely
4. Understand security headers and configurations
5. Chain multiple vulnerabilities
6. Practice responsible disclosure
7. Understand defense mechanisms

## 📊 Flag Format

All flags follow the format: `FLAG{...}`

Examples:
- `FLAG{SQL_1nj3ct10n_M4st3r_2024}`
- `FLAG{XSS_R3fl3ct3d_V1ct0ry}`
- `FLAG{1D0R_4cc3ss_C0ntr0l_F41l}`

## 🔒 Security Notice

**⚠️ WARNING**: This application is intentionally vulnerable!

- **NEVER deploy this application on a public server**
- Use only in isolated lab environments
- Do not use these techniques on systems you don't own
- For educational purposes only
- Practice responsible disclosure

## 🏗️ Architecture

```
icss_ctf/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── icss_ctf.db                 # SQLite database (auto-created)
├── templates/                  # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── courses.html
│   └── ... (20+ templates)
├── static/
│   ├── css/
│   │   └── style.css          # Styling
│   └── js/
│       ├── main.js            # Main JavaScript
│       └── config.js          # Config (with exposed secrets)
├── uploads/                    # File upload directory
├── backup/                     # Backup files (exposed)
├── logs/                       # Application logs (exposed)
└── CTF_EXPLOITATION_GUIDE.md  # Complete vulnerability guide
```

## 🐛 Troubleshooting

### Database Issues
If you encounter database errors:
```bash
rm icss_ctf.db
python app.py  # Will recreate database
```

### Port Already in Use
Change the port in `app.py`:
```python
app.run(host='0.0.0.0', port=5001, debug=False)
```

### Permission Errors
Ensure the application has write permissions:
```bash
chmod -R 755 icss_ctf/
```

## 💡 Tips for Students

1. **Start Simple**: Begin with Beginner-level challenges
2. **Read Error Messages**: They often contain valuable information
3. **Use Burp Suite**: Intercept and modify HTTP requests
4. **Check Headers**: Flags often appear in response headers
5. **View Source**: Don't forget to check HTML/JavaScript source
6. **Enumerate**: Try different IDs, usernames, parameters
7. **Combine Techniques**: Some challenges require chaining vulnerabilities
8. **Document Everything**: Keep notes of your findings
9. **Read the Guide**: When stuck, refer to `CTF_EXPLOITATION_GUIDE.md`
10. **Have Fun**: This is a learning experience!

## 🎯 Challenge Categories by Difficulty

### Beginner (10 challenges)
- HTML Comments
- JavaScript Source Exposure
- Exposed .env File
- robots.txt Disclosure
- API Data Exposure
- Default Credentials
- Reflected XSS
- Simple IDOR
- Directory Listing
- No Rate Limiting

### Intermediate (18 challenges)
- SQL Injection
- Blind SQL Injection
- Stored XSS
- Command Injection
- XXE
- SSTI
- JWT Algorithm Confusion
- JWT Weak Secret
- Privilege Escalation
- Session Fixation
- Path Traversal
- LFI
- File Upload Bypass
- CSRF
- Open Redirect
- CORS Misconfiguration
- Insecure Deserialization
- Predictable Reset Tokens

### Advanced (6 challenges)
- Chained SQL injection exploits
- Advanced SSTI with RCE
- Multi-step authentication bypass
- Complete data exfiltration
- Privilege escalation chains
- Combined XXE with SSRF

## 📈 Scoring System (Optional)

Suggested point values:
- Beginner: 10 points each (100 points total)
- Intermediate: 20 points each (360 points total)
- Advanced: 30 points each (180 points total)

**Total Possible Score**: 640 points

## 🤝 Contributing

This is an educational project. If you find additional vulnerabilities or have suggestions:
1. Document the vulnerability
2. Provide exploitation steps
3. Suggest appropriate fixes

## 📝 License

This project is for educational purposes only. Use responsibly and ethically.

## 🌟 Acknowledgments

Inspired by:
- OWASP WebGoat
- DVWA (Damn Vulnerable Web Application)
- PicoCTF
- HackTheBox
- PortSwigger Web Security Academy

## 📞 Support

For questions or issues:
1. Review the `CTF_EXPLOITATION_GUIDE.md`
2. Check application logs
3. Use debugging tools
4. Consult OWASP documentation

## 🎓 Learning Path

### Week 1: Reconnaissance
- Explore the website
- Use Burp Suite
- Capture beginner flags (10 flags)

### Week 2: Injection Attacks
- SQL Injection
- XSS attacks
- Command Injection (5 flags)

### Week 3: Authentication & Authorization
- Bypass authentication
- Privilege escalation
- Session attacks (6 flags)

### Week 4: Advanced Exploitation
- File inclusion
- SSTI
- XXE
- Deserialization (8 flags)

### Week 5: API & Configuration
- API security
- Server misconfigurations
- CORS & CSRF (5 flags)

## 🏁 Getting Started Checklist

- [ ] Install Python 3.8+
- [ ] Install dependencies (`pip install -r requirements.txt`)
- [ ] Run the application (`python app.py`)
- [ ] Access http://localhost:5000
- [ ] Install Burp Suite (optional)
- [ ] Read `CTF_EXPLOITATION_GUIDE.md`
- [ ] Capture your first flag!
- [ ] Document your findings
- [ ] Progress through difficulty levels
- [ ] Share knowledge with peers

---

**Happy Hacking! 🚩**

*Remember: With great power comes great responsibility. Use these skills ethically.*
