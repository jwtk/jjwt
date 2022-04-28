Thanks for helping make JJWT safe for everyone.

# Security Policy

The JJWT development team are security professionals who take security seriously.  However, as we are an unpaid team of volunteers, we are unable to offer a bug bounty program.  Even so, we welcome any potential good faith security reports.

## Supported Versions

As JJWT isn't yet at version 1.0, only the latest minor and point revisions are supported for security fixes.  
We ask that all users or security researchers upgrade to the latest stable release version and use that for testing before issuing a security report.

| Version  | Supported          |
| -------- | ------------------ |
| 0.11.x   | :white_check_mark: |
| < 0.11.0 | :x:                |

## Reporting Security Issues

If you believe you have found a security vulnerability in the JJWT codebase, please report it to us through coordinated disclosure.

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please send an email to security[@]jjwt.org.

Please include as much of the information listed below as you can to help us better understand and resolve the issue:

  * The type of issue (e.g., buffer overflow, invalid header behavior, etc)
  * Full paths of source file(s) related to the manifestation of the issue
  * The location of the affected source code (tag/branch/commit or direct URL)
  * Any special configuration required to reproduce the issue
  * Step-by-step instructions to reproduce the issue
  * Proof-of-concept or exploit code (if possible)
  * Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

### Valid Issues

If we find the report to be valid - that is, we recognize it as actual security issue that needs to be fixed in the codebase - 
we will work with you to identify a timeline for a public fix to be released.

Please do not publish any details related to the issue in any communication medium (blog posts, social media posts, etc) 
except via the above JJWT security email address.  This allows us to create and publish a pointfix release that 
contains the necessary fix(es) to the public before public discussion might occur, allowing JJWT users to fix their applications.  

Once the fix is publicly released, we ask for one week of time to pass to allow application developers to upgrade to this 
pointfix security release before publishing public communication or analysis (blog posts, etc) about the security vulnerability.

### Invalid Issues

If we find that a report is not a problem with the JJWT codebase - such as a problem with how JJWT is being used, or counter to or in conflict with JJWT's documentation - we 
will explain why we do not consider it a security issue and explain the expected solution.
