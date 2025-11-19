# app_scanner
This python script is designed to perform static security analysis on Android APK files built with React Native, Ionic/Capacitor, or Cordova.  The script automatically detects the underlying hybrid framework and runs the corresponding, focused security audit to identify common configuration errors and vulnerabilities.
## Requirements
- **Python 3.6**
- **apktool** installed and accessible in your system's PATH
## Features
- **Automatic Framework Detection**: Detects React Native, Ionic/Capacitor, or Cordova 
- **Focused Scanning**: Executes a specific security audit concerning the detected framework
  - Cordova/Ionic Audit: Checks for permissive configurations (```allow-navigation```, permissive access-origin), missing Content Security Policy (CSP), exposure of sensitive plugins (File, Camera, Preferences), and localStorage access risk.

React Native Audit: Checks for insecure usage of AsyncStorage or SecureStore combined with WebView data-sending mechanisms (postMessage, injectedJavaScript) and dangerous WebView flags (javascriptEnabled, addJavascriptInterface).

Structured Output: Generates a detailed JSON report suitable for integration into automated security pipelines.

Decompiled Artifacts: Retains the decompiled APK contents for manual evidence review.
