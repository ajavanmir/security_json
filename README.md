# SecurityValidator.js

This file contains a class called `SecurityValidator` that provides various security tools to validate data and protect the application against injection attacks and malicious code. These tools include the following:

## Features

1. **isBase64Strict**
Checks whether a string is valid Base64 with strict requirements, including checking for illegal characters and safe decoding.

2. **preParseSecurityCheck**
Preliminary security check to detect dangerous patterns such as JavaScript, malicious HTML code, and injection patterns.

3. **checkEncodingAndObfuscation**
Checks encoding and obfuscation patterns to prevent data misuse.

4. **deepSecurityCheck**
Deeply analyzes an array of objects to ensure that there are no dangerous keys or values.

5. **validateStringValue**
Analyze and check strings to detect malicious patterns such as JavaScript, Base64, or obfuscation methods.

6. **validateJson**
Complete tool for validating and validating JSON data, including detecting potential attacks and ensuring data security.

## Usage
This tool is designed to check the security of JSON files, prevent code injection, and protect the application from various threats. In this file, data is loaded from a JSON file, and checked using security functions before use.

## License
This project is published under **Copyright Amir Javanmir** and is submitted on November 28, 2024.
