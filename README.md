# app_scanner
This **Python** script is designed to perform **static security analysis** on **Android APK** files built with **React Native**, **Ionic/Capacitor**, or **Cordova**.  The script automatically detects the underlying hybrid framework and runs the corresponding, focused security audit to identify **common configuration errors** and **vulnerabilities**.
## Requirements
- **Python 3.6**
- **apktool** installed and accessible in your system's PATH
## Features
- **Automatic Framework Detection**: Detects React Native, Ionic/Capacitor, or Cordova 
- **Focused Scanning**: Executes a specific security audit concerning the detected framework
  - **Cordova** Checks:
    - Checks for overly broad network access settings in ```config.xml```, specifically:
      - Detects wildcards that could ```allow-navigation``` to malicious external sites
      - Detects wildcard (*) or other permissive ```access-origin``` configurations that weaken the **Same-Origin Policy**
    - Checks for a missing or weak **Content Security Policy (CSP)** ```<meta>``` tag in ```index.html```
    - Detects the presence of the **Cordova File Plugin** and usage of file system APIs (```resolveLocalFileSystemURL```), which are high-impact targets for Cross-Site Scripting (XSS) attacks
    - Detects usage of ```localStorage``` combined with permissive security configurations, indicating data exfiltration risk
    - Checks for dangerous Android configuration flags (e.g., ```android:debuggable="true"``` in the Manifest)
  - **Ionic/Capacitor** Checks:
    - Missing or weak **Content Security Policies** (```content-security-policy```)
    - Use of sensitive **Web Storage** (```localStorage.setItem```)
    - Exposure of the **Capacitor bridge** (```delete window.Capacitor```)
    - Imports and usage of sensitive **Capacitor Plugins** (Preferences, Filesystem, Clipboard, Camera)
  - **React Native** Checks:
    - Checks for the insecure usage of ```AsyncStorage``` or ```SecureStore``` (read/write operations)
    - Determines if insecure storage usage is combined with **WebView data-sending mechanisms** (```ReactNativeWebView.postMessage```) or **JavaScript injection** (```injectedJavaScript```), which allows a WebView to steal data from the main RN context
    - Checks for insecure configurations of the **WebView component** (if present in the app), such as:
      - ```javascriptEnabled: true```
      - ```originWhitelist: ['*']```
      - ```addJavascriptInterface```
- **Structured Output**: Generates a detailed JSON report suitable for integration into automated security pipelines
## Vlunerabilities
- **Cordova**:
  - localStorage data exfiltration   
  - External Script Injection accessing the Cordova File Plugin API
  - External Script Injection accessing the application HTML files
  - Same-Origin Iframe loading of malicious files accessing the Cordova File Plugin API
  - Same-Origin Iframe loading of malicious files accessing the application HTML files
- **Ionic/Capacitor**:
  - localStorage data exfiltration
  - Capacitor Preferences attack
  - Capacitor Filesystem attack
  - Same-Origin iframe accessing localStorage
  - Same-Origin Iframe accessing CapacitorPreferences Attack
  - Clipboard Attack
  - Camera Access Attack
- **React Native**:
  - AsyncStorage/SecureStore data exfiltration
  - Insecure WebView component configuration
## Usage
Run the script on a target APK:
```
python3 app_analysis.py <app.apk> -o <dir>
```
Arguments:
- **apk (required):** The path to the APK file to scan
- **-o <dir> (optional):** Specify an output directory for the decompiled contents (defaults to **/tmp** folder)
## Output
Example output snippet:
```
{
    "apk": "/path/to/app.apk",
    "framework_detection": {
        "detected": "CORDOVA",
        "reason": "Found key Cordova indicators: config.xml in res/xml, cordova.js in assets/www/"
    },
    "framework": "CORDOVA",
    "vulnerability_checks": {
        "internet_permission": true,
        "android_debuggable": false,
        "index_csp_present": false,
        "cordova_plugin_file": true,
        "resolveLocalFileSystemURL_used": true,
        "localStorage_used": true
    },
    "security_config": {
        "allow_navigation": true,
        "permissive_access_origin": true,
        "wildcard_access_origin": true
    },
    "vulnerability_verdicts": [
        "External Script Injection accessing Cordova File Plugin API (due to: CSP missing and permissive access origin configuration)",
        "External Script Injection accessing the application HTML files (due to: CSP missing and permissive access origin configuration)",
        "Same-Origin Iframe loading of malicious files accessing the Cordova File Plugin API (due to: CSP missing and permissive access origin configuration)",
        "Same-Origin Iframe loading of malicious files accessing the application HTML files (due to: CSP missing and permissive access origin configuration)",
        "localStorage data can be exfiltrated (due to: CSP missing and permissive access origin configuration)"
    ]
}
```
