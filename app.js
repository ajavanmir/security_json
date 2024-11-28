/*
Copyright amir javanmir
Released on: November 28, 2024
*/
class SecurityValidator {
    static isBase64Strict(str) {
        if (!str || typeof str !== 'string') {
            return false;
        }

        const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/gi;

        if (!base64Pattern.test(str)) {
            return false;
        }

        try {
            const decoded = atob(str);
            for (let char of decoded) {
                if (char.charCodeAt(0) > 127) {
                    return false;
                }
            }

            if (str.length < 20) {
                const decodedText = decoded.toString();
                const printableChars = decodedText.match(/[\x20-\x7E]/gi) || [];
                if (printableChars.length / decodedText.length < 0.8) {
                    return false;
                }
            }

            return btoa(decoded) === str;
        } catch (err) {
            return false;
        }
    }

    static preParseSecurityCheck(rawString) {
        const attacks = [
            /javascript:|javascript/gi,
            /<script|script/gi,
            /on\w+=/gi,
            /{{.*?}}|\${.*?}/gi,
            /{{.*?}}|\${.*?}|<%.+?%>|\[\[.+?\]\]/gi,
            /\\x[0-9A-Fa-f]{2}/i,
            /\\u[0-9A-Fa-f]{4}/i,
            /(%[0-9A-Fa-f]{2})+/i,
            /(script|javascript|window|document|remove|setAttribute|createElement|decodeURI|encodeURI|decodeURIComponent|encodeURIComponent|style|setTimeout|setInterval|XMLHttpRequest|ajax|WebSocket|fetch|delete|void|atob|btoa|localStorage|sessionStorage|caches|write|innerHTML|outerHTML|html|append|prepend|attr|prop|css|after|before|replaceWith|text|val|iframe|object|embed|base|applet|link|style|meta|jQuery|alert|confirm|prompt|function|eval|with|\bin\b|Math|getElementById|getElementsByClassName|getElementsByName|getElementsByTagName|querySelector|querySelectorAll|then|get|post|send|open|close|console|addEventListener|removeEventListener|dispatchEvent|import|require|cookie|location|jsonp|template|importScripts|execScript|call|apply|bind|constructor|prototype|__proto__|defineProperty|defineSetter|defineGetter|abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload|const|let|var|\bnew\b|\bthis\b|__defineGetter__|__defineSetter__)/gi,
            /<!--[\s\S]*?-->|\/*\*[\s\S]*?\*\/|(?<!:)\/\/[^\r\n]*/gi,
            /(?:\$|jQuery)\.?/gi,
            /<\/?\!?[a-z][\s\S]*?>/gi,
            /<!\[CDATA\[[\s\S]*?\]\]>/gi,
            /\b(class|id|style|on\w+)\s*=\s*['"].*?['"]/gi,
            /\s+[a-z-]+\s*=/gi,
            /\s+([a-z-]+)\s*=\s*["'][^"']*["']/gi,
            /\s+([a-z-]+)\s*=/gi,
            /=\s*["'][^"']*["']/gi,
            /data:/gi,
            /\\u00[0-9a-f]{2}/gi,
            /\\x[0-9a-f]{2}/gi,
            /\\\d{1,3}/gi,
            /&#x[0-9a-f]+;/gi,
            /&#\d+;/gi,
            /`[^`]*`/gi,
            /\$\{[^}]+\}/gi,
            /\[\s*['"][\s\S]*?['"]\s*\]/gi,
            /function\s*\([^)]*\)\s*{[\s\S]*?}/gi,
            /new\s+Function\s*\(/gi,
            /\(function\s*\([\s\S]*?\)\s*\{[\s\S]*?\}\s*\)/gi,
            /U\+[0-9A-Fa-f]{4,6}|U\+[0-9A-Fa-f]+|[\u200E\u200F\u202A-\u202E\u2066-\u2069]/gi,
            /\\u\{[0-9A-Fa-f]{4,6}|\\u\{[0-9A-Fa-f]+}/gi,
            /\&#x([0-9A-Fa-f]{4,6})|\&#x[0-9A-Fa-f]+/gi,
            /\\u([0-9A-Fa-f]{4,6})|\\u([0-9A-Fa-f]+)/gi
        ];

        const attackDetected = attacks.some(regex => regex.test(rawString));
        if (attackDetected) {
            throw new Error('Pre-parse security attack detected!');
        }

        this.checkEncodingAndObfuscation(rawString);
    }

    static checkEncodingAndObfuscation(rawString) {
        const encodingPatterns = [
            /0x[0-9A-Fa-f]{2}/gi,
            /0x[0-9A-Fa-f]{4}/gi,
            /0x[0-9A-Fa-f]{8}/gi,
            /\\u[0-9A-Fa-f]{4}/gi,
            /&#x[0-9A-Fa-f]+;/gi
        ];

        const encodingDetected = encodingPatterns.some(regex => regex.test(rawString));
        if (encodingDetected) {
            throw new Error('Encoding patterns detected before parsing!');
        }

        const obfuscationPatterns = [
            /\.join\(/,
            /\[[^\]]*\]\.join/,
            /["']\s*\+\s*["']/,
            /fromcharcode/i,
            /\.charat/i,
            /\.(substring|substr|slice)/i
        ];

        const obfuscationDetected = obfuscationPatterns.some(regex => regex.test(rawString));
        if (obfuscationDetected) {
            throw new Error('Obfuscation patterns detected before parsing!');
        }

        const base64Regex = /(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)/ig;
        const base64Matches = rawString.match(base64Regex);

        if (base64Matches && base64Matches.some(this.isBase64Strict)) {
            throw new Error('Unexpected Base64 encoding detected!');
        }
    }

    static deepSecurityCheck(data) {
        if (!Array.isArray(data)) {
            throw new Error("Input must be an array of objects!");
        }

        const VALID_KEYS = [
            'Your Validate Keys'
        ];

        const MAX_KEYS = VALID_KEYS.length;

        data.forEach((item) => {
            if (typeof item !== 'object' || item === null) {
                throw new Error("Each item must be an object!");
            }

            const entries = Object.entries(item);
            if (entries.length > MAX_KEYS) {
                throw new Error("Excessive number of keys!");
            }

            entries.forEach(([key, value]) => {
                const dangerousKeys = [
                    '__proto__', 'constructor', 'prototype',
                    '__defineGetter__', '__defineSetter__',
                    'caller', 'callee', 'arguments',
                    'Function', 'eval'
                ];

                if (dangerousKeys.some(dangerousKey =>
                    key === dangerousKey ||
                    key.startsWith('__') ||
                    /(defineProperty|defineGetter|defineSetter|caller|callee|arguments|eval)/i.test(key)
                )) {
                    throw new Error(`Dangerous key detected: ${key}`);
                }

                if (!VALID_KEYS.includes(key)) {
                    throw new Error(`Invalid key: ${key}`);
                }

                if (value !== null && !['string', 'number'].includes(typeof value)) {
                    throw new Error(`Invalid value type for key ${key}`);
                }

                if (typeof value === 'string' && value.trim().length > 0) {
                    this.validateStringValue(key, value);
                }
            });
        });
    }

    static validateStringValue(key, value) {
        const obfuscationPatterns = [
            /\.join\(/,
            /\[[^\]]*\]\.join/,
            /["']\s*\+\s*["']/,
            /fromcharcode/i,
            /\.charat/i,
            /\.(substring|substr|slice)/i
        ];

        if (obfuscationPatterns.some(pattern => pattern.test(value))) {
            throw new Error(`Obfuscation detected in: ${key}`);
        }

        const attackPatterns = [
            /javascript:|script/gi,
            /on\w+=/gi,
            /{{.*?}}|\${.*?}/gi,
            /\\x[0-9A-Fa-f]{2}/i,
            /=['"].*?['"]/gi,
            /['"].*?['"]/gi,
            /\b(eval|function|window|document)\b/gi
        ];

        if (attackPatterns.some(pattern => pattern.test(value))) {
            throw new Error(`Security attack detected in: ${key}`);
        }

        const base64Regex = /(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)/ig;
        const matches = value.match(base64Regex);

        if (matches && matches.some(val => this.isBase64Strict(val))) {
            throw new Error(`Base64 encoding detected in: ${key}`);
        }
    }
}

function validateJson(jsonString) {
    try {
        if (jsonString.trim().length > 0) {
            SecurityValidator.preParseSecurityCheck(jsonString);
            const parsedData = JSON.parse(jsonString);
            SecurityValidator.deepSecurityCheck(parsedData);
            return parsedData;
        } else {
            throw new Error('Not Content!');
        }

    } catch (error) {
        console.error(`JSON Validation Error: ${error.message}`);
        return null;
    }
}

window.onload = function () {
    fetch("./file.json")
        .then(response => response.text())
        .then(responseText => {
            let jsonText = validateJson(responseText);
            if (jsonText) {
                console.log(jsonText);
            }
        })
        .catch(error => {
            console.error("Fetch error:", error);
        });
};