## M04:2024 — Insufficient Input / Output Validation
**🟠 High** | CWE-20 · CWE-79 · CWE-89

> Mobile apps pass user input to local databases, web views,  
> and backend APIs without sanitizing — enabling injection and XSS.

--

## How It Works + Real-World Example

**SQLite injection on device:**

```java
// VULNERABLE — local SQLite injection
String query = "SELECT * FROM notes WHERE title LIKE '%" + userInput + "%'";
db.rawQuery(query, null);
// Input: ' UNION SELECT password,2,3 FROM users--
// → leaks password column from local DB
```

**WebView XSS:**
```java
// VULNERABLE — loading user content in WebView
webView.loadUrl("file:///android_asset/viewer.html#" + userInput);
webView.getSettings().setJavaScriptEnabled(true);
// Attacker injects: <script>Android.readFile('/sdcard/private.txt')</script>
```

**Real-world — TikTok in-app browser (2022)**: Security researcher Felix Krause documented that TikTok's in-app WebView injected JavaScript into every loaded page — capturing keystrokes, form input, and taps. While used for analytics, the same injection mechanism enables XSS escalation to native Android bridges.

Note: SQLite = the embedded relational database used by virtually all mobile apps for local data storage. WebView = an in-app browser component that renders HTML/CSS/JS — if it can call native Android APIs (via JavaScript bridges), XSS in the WebView escalates to native code access. XSS = Cross-Site Scripting. Android JavaScript interfaces (addJavascriptInterface) create a bridge between WebView JavaScript and native Java methods.

--

## Mitigation & References

```java
// FIXED — parameterized local SQLite query
Cursor cursor = db.query(
    "notes",
    new String[]{"title", "content"},
    "title LIKE ?",
    new String[]{"%" + userInput + "%"},  // parameterized
    null, null, null
);

// FIXED — disable JavaScript in WebViews that don't need it
webView.getSettings().setJavaScriptEnabled(false);
// Or: use DOMPurify for content that must render HTML
```

| Resource | Details |
|---|---|
| [OWASP MASTG Input Validation](https://mas.owasp.org/MASTG/) | Mobile testing guide |
| Android Room ORM | Parameterized queries by default |
| MobSF | Detects raw SQL and WebView misuse |
