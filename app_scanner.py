#!/usr/bin/env python3

import os
import sys
import subprocess
import zipfile
import re
import json
import argparse
import tempfile
import shutil
from pathlib import Path

# Common to any scanner

TEXT_EXTS = {'.js', '.ts', '.html', '.htm', '.json', '.xml', '.smali', '.java', '.kt', '.txt', '.properties', '.bundle', '.css', '.scss'}
MAX_READ = 2_000_000 

def run_cmd(cmd, cwd=None):
    """Execute a shell command."""
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def safe_read(path):
    """Read file content safely, with binary fallback."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")
    except Exception:
        return ""

def decompile_apk(apk_path, out_dir):
    """Decompile APK using apktool (or unzip as a fallback)."""
    out_dir = os.path.abspath(out_dir)
    apktool_out = os.path.join(out_dir, "apktool_out")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Decompiling APK to {apktool_out} (apktool preferred)...", file=sys.stderr)
    rc, out, err = run_cmd(["apktool", "d", "-f", apk_path, "-o", apktool_out])
    if rc == 0:
        return apktool_out

    print("[!] apktool failed. Falling back to unzip.", file=sys.stderr)
    unzipped = os.path.join(out_dir, "unzipped")
    os.makedirs(unzipped, exist_ok=True)
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            z.extractall(unzipped)
        return unzipped
    except Exception as e:
        print(f"[!] Failed to unpack APK: {e}", file=sys.stderr)
        return None

def read_manifest_for_flags(manifest_path):
    """Read AndroidManifest.xml for key flags (Cordova/Capacitor/Debuggable)."""
    try:
        text = safe_read(manifest_path)
        has_internet = 'android.permission.INTERNET' in text
        has_bridge = 'com.getcapacitor.BridgeActivity' in text
        has_cordova_activity = 'org.apache.cordova.CordovaActivity' in text
        is_debuggable = re.search(r'android:debuggable\s*=\s*"true"', text, re.IGNORECASE) is not None
        return has_internet, has_bridge, has_cordova_activity, is_debuggable
    except Exception:
        return False, False, False, False

# Framework Detection

def detect_framework(decompiled_path):
    """
    Determines the most likely framework: React Native, Ionic/Capacitor, or Cordova.
    Returns: ('FRAMEWORK', 'Reason')
    """
    
    # 1. React Native
    rn_indicators = {
        'bundle': any(f.endswith(".bundle") or f.endswith(".hbc") for root, _, files in os.walk(os.path.join(decompiled_path, "assets")) for f in files),
        'smali_rn': any("com/facebook/react" in root.replace("\\", "/") for root, _, _ in os.walk(decompiled_path)),
        'lib_rn': any(f.lower().startswith("libreactnative") or "hermes" in f.lower() for root, _, files in os.walk(decompiled_path) for f in files if f.endswith(".so")),
    }
    if any(rn_indicators.values()):
        reason = [k for k, v in rn_indicators.items() if v]
        return 'REACT_NATIVE', f"Found key RN indicators: {', '.join(reason)}"

    # 2. Ionic (Capacitor) 
    manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml")
    _, has_capacitor_bridge, has_cordova_activity, _ = read_manifest_for_flags(manifest_path)

    capacitor_config = os.path.exists(os.path.join(decompiled_path, "assets", "capacitor.config.json"))
    ionic_markers = any('ionic' in safe_read(p).lower() for p in (os.path.join(decompiled_path, "assets", "index.html"), os.path.join(decompiled_path, "assets", "main.js")))

    if has_capacitor_bridge or capacitor_config or ionic_markers:
        reason = []
        if has_capacitor_bridge: reason.append("Capacitor BridgeActivity in manifest")
        if capacitor_config: reason.append("capacitor.config.json")
        if ionic_markers: reason.append("Ionic markers (ion-) in assets")
        return 'IONIC_CAPACITOR', f"Found key Ionic/Capacitor indicators: {', '.join(reason)}"

    # 3. Cordova 
    cordova_config = os.path.exists(os.path.join(decompiled_path, "res", "xml", "config.xml"))
    cordova_js = os.path.exists(os.path.join(decompiled_path, "assets", "www", "cordova.js"))

    if has_cordova_activity or cordova_config or cordova_js:
        reason = []
        if has_cordova_activity: reason.append("CordovaActivity in manifest")
        if cordova_config: reason.append("config.xml in res/xml")
        if cordova_js: reason.append("cordova.js in assets/www/")
        return 'CORDOVA', f"Found key Cordova indicators: {', '.join(reason)}"
        
    return 'UNKNOWN', "No specific framework indicators found"

# React Native Scanner

def react_native_scan(decompiled_path):
    """Performs the React Native specific security analysis."""
    # Define patterns specific to RN/WebView/AsyncStorage
    PATTERNS = {
        "async_get": re.compile(r"AsyncStorage\.(getItem|setItem)|getItemAsync\(", re.IGNORECASE),
        "secure_get": re.compile(r"SecureStore\.getItemAsync|Keychain|react-native-keychain", re.IGNORECASE),
        "postmessage": re.compile(r"ReactNativeWebView\.postMessage|postMessage\s*\(", re.IGNORECASE),
        "injected_js": re.compile(r"injectedJavaScript|injectedJavaScriptBeforeContentLoaded|window\.username", re.IGNORECASE),
        "javascript_enabled": re.compile(r"javascriptEnabled\s*=\s*{?\s*(true|True)\s*}?", re.IGNORECASE),
        "origin_whitelist_all": re.compile(r"originWhitelist\s*=\s*{?\s*\[?\s*['\"]\*\s*['\"]\s*\]?", re.IGNORECASE),
        "add_js_interface": re.compile(r"addJavascriptInterface\b", re.IGNORECASE),
        "allow_file_access": re.compile(r"allowFileAccess\b|setAllowFileAccess\b|allowFileAccessFromFileURLs", re.IGNORECASE),
    }

    def collect_scan_paths_rn(base_dir):
        paths = set()
        for root, _, files in os.walk(base_dir):
            if "AndroidManifest.xml" in files: paths.add(os.path.join(root, "AndroidManifest.xml"))
            if "assets" in root.split(os.sep) or "/assets/" in root.replace("\\","/"):
                for f in files:
                    if f.lower().endswith((".js", ".html", ".htm", ".bundle", ".json")) or "index.android" in f.lower(): paths.add(os.path.join(root, f))
            if "smali" in root.split(os.sep) or "smali" in root.lower():
                for f in files:
                    if f.lower().endswith((".smali", ".java", ".kt")): paths.add(os.path.join(root, f))
        return sorted(paths)

    def scan_paths_for_patterns_rn(paths):
        findings = {}
        for p in paths:
            txt = safe_read(p)
            matched = []
            if not txt: continue

            for key, pat in PATTERNS.items():
                m = pat.search(txt)
                if m:
                    snippet = txt[max(0, m.start()-120):m.end()+120].replace("\n","\\n")
                    matched.append({"pattern": key, "snippet": snippet})
            if matched:
                findings[p] = matched
        return findings

    def evaluate_findings_rn(findings):
        storage_hits = []
        send_hits = []
        webview_flags = []

        for f, matches in findings.items():
            for m in matches:
                pat = m["pattern"]
                if pat in ("async_get", "secure_get"):
                    storage_hits.append((f, m))
                if pat in ("postmessage", "injected_js"):
                    send_hits.append((f, m))
                if pat in ("javascript_enabled", "origin_whitelist_all", "allow_file_access", "add_js_interface"):
                    webview_flags.append((f, m))

        async_vulnerable = (len(storage_hits) > 0 and len(send_hits) > 0)
        webview_vulnerable = (len(webview_flags) > 0)

        return {
            "async_vulnerable": async_vulnerable,
            "webview_vulnerable": webview_vulnerable,
            "vulnerability_verdicts": [
                "AsyncStorage/SecureStore data exfiltration risk (Read storage + Webview injection/postMessage used)"
            ] if async_vulnerable else [] + [
                "Insecure WebView component configuration (e.g., JavaScript enabled, wildcard origin, addJavascriptInterface)"
            ] if webview_vulnerable else [],
            "evidence": {
                "storage_hits": [{"file": f, "snippet": m["snippet"]} for (f,m) in storage_hits],
                "send_hits": [{"file": f, "snippet": m["snippet"]} for (f,m) in send_hits],
                "webview_flags": [{"file": f, "pattern": m["pattern"], "snippet": m["snippet"]} for (f,m) in webview_flags],
            }
        }

    # Run React Native Scanner
    paths = collect_scan_paths_rn(decompiled_path)
    findings = scan_paths_for_patterns_rn(paths)
    result = evaluate_findings_rn(findings)

    # Final Results
    return {
        "framework": "REACT_NATIVE",
        "async_storage_exfiltration_vulnerable": bool(result["async_vulnerable"]),
        "insecure_webview_components_vulnerable": bool(result["webview_vulnerable"]),
        "vulnerability_verdicts": result["vulnerability_verdicts"],
        # This can be uncommented to show the files where the vulnerabilities have been found
        #"evidence": result["evidence"] 
    }

# Ionic (Capacitor) Scanner

def ionic_scan(decompiled_dir):
    """Performs the Ionic/Capacitor specific security analysis."""
    assets_dir = os.path.join(decompiled_dir, "assets")
    if not os.path.isdir(assets_dir): assets_dir = decompiled_dir

    patterns = {
        'localStorage.setItem': 'localStorage.setItem',
        'meta.csp': 'content-security-policy',
        'delete.window.Capacitor': 'delete window.Capacitor',
        'capacitor.preferences.import': '@capacitor/preferences',
        'capacitor.plugins.preferences': 'capacitor.plugins.preferences',
        'capacitor.filesystem.import': '@capacitor/filesystem',
        'filesystem.writeFile': 'writeFile(',
        'capacitor.clipboard.import': '@capacitor/clipboard',
        'clipboard.read': 'clipboard.read',
        'capacitor.camera.import': '@capacitor/camera',
        'camera.getPhoto': 'getPhoto(',
        'capacitor.plugins': 'Capacitor.Plugins',
        'iframe.assets': '/assets/',
    }

    def is_csp_present(decompiled_path):
        pattern = re.compile(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\']', re.IGNORECASE)
        for root, _, files in os.walk(decompiled_path):
            for file in files:
                if file.endswith(".html"):
                    path = os.path.join(root, file)
                    try:
                        if pattern.search(safe_read(path)): return True
                    except Exception: continue
        return False
        
    def iter_text_files_ionic(root):
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                ext = os.path.splitext(fn)[1].lower()
                try:
                    if ext in TEXT_EXTS or os.path.getsize(full) < 200_000: yield full
                except Exception: continue

    def file_grep_ionic(filepath, pattern):
        out = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for i, line in enumerate(f, start=1):
                    if pattern.lower() in line.lower(): out.append((i, line.rstrip()))
        except Exception: pass
        return out
    
    def search_all_ionic(root, patterns):
        results = {k: [] for k in patterns.keys()}
        for path in iter_text_files_ionic(root):
            for key, pat in patterns.items():
                hits = file_grep_ionic(path, pat)
                for lineno, line in hits:
                    results[key].append(path) 
        return results

    # Run Ionic (Capacitor) scanner
    found = search_all_ionic(assets_dir, patterns)
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    has_internet, _, _, _ = read_manifest_for_flags(manifest_path)
    
    csp_present = is_csp_present(assets_dir)
    
    # Summary of which indicators exist (True/False)
    checks = {
        'internet_permission': has_internet,
        'csp_missing': not csp_present,
        'delete_window_capacitor': len(found.get('delete.window.Capacitor', [])) > 0,
        'localStorage_setItem': len(found.get('localStorage.setItem', [])) > 0,
        'iframe_assets': len(found.get('iframe.assets', [])) > 0,
        'preferences_import': len(found.get('capacitor.preferences.import', [])) > 0,
        'filesystem_import': len(found.get('capacitor.filesystem.import', [])) > 0,
        'filesystem_writefile': len(found.get('filesystem.writeFile', [])) > 0,
        'clipboard_import': len(found.get('capacitor.clipboard.import', [])) > 0,
        'camera_import': len(found.get('capacitor.camera.import', [])) > 0,
    }

    # Vulnerability Verdicts
    bridge_exposed = not checks['delete_window_capacitor']
    vulnerability_verdicts = []
    
    # 1. localStorage Attack
    if checks['localStorage_setItem'] and checks['csp_missing']:
        vulnerability_verdicts.append("localStorage attack (due to: CSP missing and localStorage.setItem usage)")
    
    # 2. capacitorPreferences Attack
    if checks['preferences_import'] and checks['csp_missing'] and bridge_exposed:
        vulnerability_verdicts.append("Capacitor Preferences attack (due to: CSP missing and bridge exposed)")

    # 3. capacitorFileSystem Attack
    if checks['filesystem_import'] and checks['filesystem_writefile'] and checks['csp_missing'] and bridge_exposed:
        vulnerability_verdicts.append("Capacitor Filesystem attack (due to: CSP missing, writeFile usage, and bridge exposed)")

    # 4. Same-Origin iframe accessing localStorage Attack
    if checks['iframe_assets'] and checks['localStorage_setItem'] and checks['csp_missing']:
        vulnerability_verdicts.append("Same-Origin iframe accessing localStorage (due to: CSP missing and iframe loading /assets/)")

    # 5. Same-Origin Iframe accessing CapacitorPreferences Attack
    if checks['iframe_assets'] and checks['preferences_import'] and checks['csp_missing'] and bridge_exposed:
        vulnerability_verdicts.append("Same-Origin Iframe accessing CapacitorPreferences Attack (due to: CSP missing, Preferences plugin imported, iframe loading /assets/, and Capacitor bridge exposed)")

    # 6. Clipboard Attack
    if checks['clipboard_import'] and checks['csp_missing'] and bridge_exposed:
        vulnerability_verdicts.append("Clipboard Attack (due to: CSP missing, Clipboard plugin imported, and Capacitor bridge exposed)")

    # 7. Camera Access Attack
    if checks['camera_import'] and checks['csp_missing'] and bridge_exposed:
        vulnerability_verdicts.append("Camera Access Attack (due to: CSP missing, Camera plugin imported, and Capacitor bridge exposed)")

    # Final Results
    return {
        "framework": "IONIC_CAPACITOR",
        "vulnerability_checks": checks,
        "vulnerability_verdicts": vulnerability_verdicts,
        #"evidence_files": {k: v for k, v in found.items() if v}
    }

# Cordova Scanner

def cordova_scan(decoded_dir):
    """Performs the Cordova specific security analysis."""
    REPORT = {}
    android_ns = "{http://schemas.android.com/apk/res/android}"
    
    import xml.etree.ElementTree as ET 

    def check_manifest(decoded_dir):
        manifest_file = os.path.join(decoded_dir, "AndroidManifest.xml")
        try:
            tree = ET.parse(manifest_file)
            root = tree.getroot()
            permissions = [p.attrib.get(f"{android_ns}name") for p in root.findall("uses-permission")]
            REPORT["internet_permission"] = "android.permission.INTERNET" in permissions
            app_tag = root.find("application")
            if app_tag is not None:
                debug_attr = app_tag.attrib.get(f"{android_ns}debuggable", "false")
                REPORT["android_debuggable"] = (debug_attr.lower() == "true")
            else:
                REPORT["android_debuggable"] = False 
        except Exception:
            REPORT["internet_permission"] = False
            REPORT["android_debuggable"] = False
    
    def check_allow_navigation(decoded_dir):
        config_file = os.path.join(decoded_dir, "res/xml/config.xml")
        if not os.path.exists(config_file):
            REPORT["allow_navigation"] = False
            return
        try:
            content = safe_read(config_file)
            content_no_comments = re.sub(r"", "", content, flags=re.DOTALL)
            root = ET.fromstring(content_no_comments)
            ns = {"w": "http://www.w3.org/ns/widgets"}
            allow_navigation_tags = root.findall("w:allow-navigation", ns)
            REPORT["allow_navigation"] = len(allow_navigation_tags) > 0
        except Exception:
            REPORT["allow_navigation"] = False

    def check_access_origin_cordova(decoded_dir):
        """Check for <access origin> tags in config.xml"""
        config_file = os.path.join(decoded_dir, "res/xml/config.xml")
        if not os.path.exists(config_file):
            REPORT["wildcard_access_origin"] = False
            REPORT["permissive_access_origin"] = False
            return
        
        try:
            tree = ET.parse(config_file)
            root = tree.getroot()

            ns = {"def": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}

            access_tags = root.findall(".//def:access", ns) if ns else root.findall(".//access")

            if not access_tags:
                REPORT["wildcard_access_origin"] = False
                REPORT["permissive_access_origin"] = False
            else:
                access_origins = [access.attrib.get("origin", "") for access in access_tags]
                
                REPORT["wildcard_access_origin"] = "*" in access_origins
                
                # Check for permissive access origins
                permissive_patterns = ["*", "http://*", "https://*", "file://*"]
                permissive_origins_found = [acc for acc in access_origins 
                                    if acc in permissive_patterns or 
                                       acc.startswith("http://") or 
                                       acc.startswith("https://")]
                REPORT["permissive_access_origin"] = len(permissive_origins_found) > 0

        except Exception:
            REPORT["wildcard_access_origin"] = False
            REPORT["permissive_access_origin"] = False

    def check_plugin_file(decoded_dir):
        plugin_path = os.path.join(decoded_dir, "assets/www/plugins/cordova-plugin-file")
        REPORT["cordova_plugin_file"] = os.path.isdir(plugin_path)

    def check_index_csp(decoded_dir):
        index_file = os.path.join(decoded_dir, "assets/www/index.html")
        if not os.path.exists(index_file): REPORT["index_csp"] = False; REPORT["resolveLocalFileSystemURL_used"] = False; return
        try:
            content = safe_read(index_file)
            content_no_comments = re.sub(r"", "", content, flags=re.DOTALL)
            REPORT["index_csp"] = re.search(r'<meta[^>]+Content-Security-Policy', content_no_comments, re.IGNORECASE) is not None
            REPORT["resolveLocalFileSystemURL_used"] = "resolveLocalFileSystemURL" in content_no_comments or any(
                "resolveLocalFileSystemURL" in safe_read(p) for root, _, files in os.walk(os.path.join(decoded_dir, "assets/www")) 
                for f in files if f.endswith(".js") and (p := os.path.join(root, f))
            )
            localStorage_used_in_html = re.search(r'localStorage\.(getItem|setItem|removeItem|clear)', content_no_comments, re.IGNORECASE) is not None
            localStorage_used_in_js = any(
                re.search(r'localStorage\.(getItem|setItem|removeItem|clear)', safe_read(p), re.IGNORECASE) for root, _, files in os.walk(os.path.join(decoded_dir, "assets/www")) 
                for f in files if f.endswith(".js") and (p := os.path.join(root, f))
            )
            REPORT["localStorage_used"] = localStorage_used_in_html or localStorage_used_in_js
        except Exception:
            REPORT["index_csp"] = False; REPORT["resolveLocalFileSystemURL_used"] = False; REPORT["localStorage_used"] = False

    # Run Cordova checks
    check_manifest(decoded_dir)
    check_allow_navigation(decoded_dir)
    check_access_origin_cordova(decoded_dir)
    check_plugin_file(decoded_dir)
    check_index_csp(decoded_dir)

    # Vulnerability Verdicts
    vulns = []
    csp_missing = REPORT.get("index_csp") is False
    internet = REPORT.get("internet_permission") is True
    cordova_plugin_file = REPORT.get("cordova_plugin_file") is True
    allow_navigation = REPORT.get("allow_navigation") is True
    resolve_used = REPORT.get("resolveLocalFileSystemURL_used") is True
    permissive_access = REPORT.get("permissive_access_origin") is True
    is_debuggable = REPORT.get("android_debuggable") is True
    localStorage_used = REPORT.get("localStorage_used") is True

    security_weakness = csp_missing or permissive_access

    # 1. localStorage Exfiltration
    if security_weakness and internet and localStorage_used:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"localStorage data exfiltration (due to: {', '.join(reason)})") 

    # 2. localStorage Exfiltration
    if security_weakness and internet and localStorage_used and allow_navigation:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"Same-Origin Iframe exfiltrating localStorage (due to: {', '.join(reason)})") 

    # 3. External Script Injection accessing File Plugin API
    if security_weakness and internet and cordova_plugin_file and resolve_used:
        reason = []; 
        if csp_missing: reason.append("CSP missing"); 
        if permissive_access: reason.append("permissive access origin");
        vulns.append(f"External Script Injection accessing Cordova File Plugin API (due to: {', '.join(reason)})")

    # 4. External Script Injection accessing HTML files
    if security_weakness and internet:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"External Script Injection accessing the application HTML files (due to: {', '.join(reason)})")

    # 5. Same-Origin Iframe accessing File Plugin API
    if security_weakness and internet and cordova_plugin_file and resolve_used and allow_navigation:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"Same-Origin Iframe loading of malicious files accessing the Cordova File Plugin API (due to: {', '.join(reason)})")

    # 6. Same-Origin Iframe accessing HTML files
    if security_weakness and internet and allow_navigation:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"Same-Origin Iframe loading of malicious files accessing the application HTML files (due to: {', '.join(reason)})") 

        # 2. App is debuggable
    # if is_debuggable:
    #     vulns.append("Application is debuggable (android:debuggable=\"true\"), exposing it to remote debugging and data theft")
    #
    # # 3. Wildcard access origin vulnerability (specific case)
    # if REPORT.get("wildcard_access_origin") is True:
    #     vulns.append("Wildcard access origin (*) allows unrestricted external access")
        
    # Final Results
    final_report = {
        "framework": "CORDOVA",
        "vulnerability_checks": {
            "internet_permission": internet,
            "android_debuggable": is_debuggable,
            "index_csp_present": REPORT.get("index_csp"),
            "cordova_plugin_file": cordova_plugin_file,
            "resolveLocalFileSystemURL_used": resolve_used,
            "localStorage_used": localStorage_used
        },
        "security_config": {
            "allow_navigation": allow_navigation,
            "permissive_access_origin": permissive_access,
            "wildcard_access_origin": REPORT.get("wildcard_access_origin")
        },
        "vulnerability_verdicts": vulns if vulns else ["No vulnerabilities detected"],
    }
    return final_report

# Main Function 

def main():
    parser = argparse.ArgumentParser(description="Hybrid Mobile App Security Scanner (Unified)")
    parser.add_argument("apk", help="APK file to scan")
    parser.add_argument("--out", help="optional output directory for decompiled folder (default: temporary)", default=None)
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        print(f"[!] APK not found: {apk_path}", file=sys.stderr)
        sys.exit(1)

    # Choose output directory
    if args.out:
        out_dir = os.path.abspath(args.out)
    else:
        base = Path(tempfile.gettempdir())
        out_dir = base / f"hybrid_scan_{Path(apk_path).stem}"
        i = 1
        while out_dir.exists():
            out_dir = base / f"hybrid_scan_{Path(apk_path).stem}_{i}"
            i += 1
    
    temp_out_dir = Path(out_dir)

    try:
        # Decompile
        decompiled_path = decompile_apk(apk_path, temp_out_dir)
        if not decompiled_path:
            raise Exception("Decompilation failed.")

        # Framework Detection
        framework, reason = detect_framework(decompiled_path)
        print(f"\n[+] Detected Framework: **{framework}** ({reason})", file=sys.stderr)
        print(f"[*] Running {framework} specific security audit...", file=sys.stderr)
        
        final_report = {"apk": apk_path, "framework_detection": {"detected": framework, "reason": reason}}

        # Run the appropriate scanner
        if framework == 'REACT_NATIVE':
            analysis_result = react_native_scan(decompiled_path)
        elif framework == 'IONIC_CAPACITOR':
            analysis_result = ionic_scan(decompiled_path)
        elif framework == 'CORDOVA':
            analysis_result = cordova_scan(decompiled_path)
        else:
            analysis_result = {"status": "Analysis skipped: Unknown framework"}

        final_report.update(analysis_result)

        # Print the final JSON data to standard output
        print("\n=== FINAL UNIFIED ANALYSIS REPORT ===")
        print(json.dumps(final_report, indent=4))
        
        # Print the retained folder path
        print(f"\n[+] Decompiled folder retained at: {decompiled_path}", file=sys.stderr)
        print("[*] Inspect the decompiled folder manually for file-level evidence.", file=sys.stderr)

    except Exception as e:
        print(f"[!] A fatal error occurred: {e}", file=sys.stderr)
        if not args.out and 'decompiled_path' in locals() and Path(decompiled_path).exists():
             shutil.rmtree(decompiled_path)
        sys.exit(1)
    finally:
        # If a temporary parent directory was created and no --out was specified, clean up
        if not args.out and temp_out_dir.exists():
            # If apktool_out, it means the path was correctly returned, but the empty parent can be removed if it's the auto-created temp folder.
            pass


if __name__ == "__main__":
    # Ensure XML parser is available for Cordova/Ionic manifest/config checks
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        print("[!] Error: xml.etree.ElementTree not found. This should be part of standard Python. Cannot run Cordova/Ionic manifest checks.", file=sys.stderr)
        sys.exit(1)
    
    main()
