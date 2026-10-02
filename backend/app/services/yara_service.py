"""
ThreatLens AI - Real YARA Analysis Engine
Loads, compiles, and matches real .yar rules against uploaded file bytes.
Supports both native yara-python (when compiled) and an integrated pure-Python
YARA parser/engine for universal platform compatibility (e.g. Python 3.14 Windows).
Strict zero-execution byte inspection.
"""

import os
import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check for native C-based yara
try:
    import yara  # type: ignore
    HAS_NATIVE_YARA = True
except (ImportError, Exception):
    HAS_NATIVE_YARA = False
    logger.info("Native yara-python not available. Using built-in universal YARA engine.")

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


class FallbackYaraRule:
    """Represents a parsed .yar rule for pure-Python execution."""
    def __init__(self, name: str, tags: List[str], meta: Dict[str, str], strings: Dict[str, Dict[str, Any]], condition: str):
        self.name = name
        self.tags = tags
        self.meta = meta
        self.strings = strings  # key: '$identifier' -> {'pattern': bytes, 'nocase': bool}
        self.condition = condition

    def match(self, data: bytes) -> Optional[Dict[str, Any]]:
        # Match each string definition
        matches = {}
        for var_name, spec in self.strings.items():
            pattern = spec["pattern"]
            nocase = spec["nocase"]
            if nocase:
                found = bool(re.search(re.escape(pattern), data, re.IGNORECASE))
            else:
                found = pattern in data
            matches[var_name] = found

        # Evaluate condition
        matched = False
        cond = self.condition.strip()

        # Handle "N of them"
        n_of_them_match = re.match(r"(\d+)\s+of\s+them", cond, re.IGNORECASE)
        if n_of_them_match:
            required = int(n_of_them_match.group(1))
            matched = sum(1 for v in matches.values() if v) >= required
        elif " or " in cond or " and " in cond or cond.startswith("$"):
            # Safe evaluation by replacing var names with boolean values
            eval_expr = cond
            for var_name, is_match in matches.items():
                eval_expr = re.sub(re.escape(var_name) + r"\b", str(is_match), eval_expr)
            eval_expr = re.sub(r"\band\b", "and", eval_expr, flags=re.IGNORECASE)
            eval_expr = re.sub(r"\bor\b", "or", eval_expr, flags=re.IGNORECASE)
            eval_expr = re.sub(r"\bnot\b", "not", eval_expr, flags=re.IGNORECASE)
            try:
                # Restrict eval globals and locals
                matched = bool(eval(eval_expr, {"__builtins__": {}}, {}))
            except Exception:
                # Fallback: if any defined string matched
                matched = any(matches.values())
        else:
            matched = any(matches.values())

        if matched:
            matched_string_list = [
                f"{k}: {spec['pattern'].decode('utf-8', errors='ignore')}"
                for k, spec in self.strings.items() if matches.get(k)
            ]
            return {
                "rule_name": self.name,
                "tags": self.tags,
                "meta": self.meta,
                "severity": self.meta.get("severity", "medium"),
                "description": self.meta.get("description", f"Matched YARA rule: {self.name}"),
                "matched_strings": matched_string_list
            }
        return None


def parse_yar_file(filepath: str) -> List[FallbackYaraRule]:
    """Parses standard .yar rule files into structured executable rules."""
    rules = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Regex to extract rule blocks
        rule_pattern = re.compile(
            r"rule\s+([A-Za-z0-9_]+)(?:\s*:\s*([^{]+))?\s*\{(.*?)\}",
            re.DOTALL
        )

        for match in rule_pattern.finditer(content):
            rule_name = match.group(1)
            raw_tags = match.group(2) or ""
            tags = [t.strip() for t in raw_tags.split() if t.strip()]
            body = match.group(3)

            meta: Dict[str, str] = {}
            strings: Dict[str, Dict[str, Any]] = {}
            condition = ""

            # Extract meta
            meta_match = re.search(r"meta:\s*(.*?)(?=strings:|condition:|\Z)", body, re.DOTALL)
            if meta_match:
                for line in meta_match.group(1).strip().splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        meta[k.strip()] = v.strip().strip('"').strip("'")

            # Extract strings
            strings_match = re.search(r"strings:\s*(.*?)(?=condition:|\Z)", body, re.DOTALL)
            if strings_match:
                for line in strings_match.group(1).strip().splitlines():
                    line = line.strip()
                    if line.startswith("$") and "=" in line:
                        var_part, val_part = line.split("=", 1)
                        var_name = var_part.strip()
                        val_part = val_part.strip()
                        nocase = "nocase" in val_part.lower()
                        # Extract quoted string literal
                        str_val_match = re.search(r'"([^"]*)"', val_part)
                        if str_val_match:
                            str_val = str_val_match.group(1).encode("utf-8")
                            strings[var_name] = {"pattern": str_val, "nocase": nocase}

            # Extract condition
            cond_match = re.search(r"condition:\s*(.*?)\Z", body, re.DOTALL)
            if cond_match:
                condition = cond_match.group(1).strip()

            rules.append(FallbackYaraRule(rule_name, tags, meta, strings, condition))
    except Exception as e:
        logger.error(f"Error parsing YARA rule file {filepath}: {e}")
    return rules


class ThreatLensYaraEngine:
    """Manages compiled rules and executes matching against file bytes."""
    def __init__(self, rules_dir: str = RULES_DIR):
        self.rules_dir = rules_dir
        self.native_rules = None
        self.fallback_rules: List[FallbackYaraRule] = []
        self._load_and_compile()

    def _load_and_compile(self):
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)

        yar_files = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    path = os.path.join(root, file)
                    yar_files[file] = path

        if not yar_files:
            logger.warning(f"No YARA rules found in {self.rules_dir}")
            return

        if HAS_NATIVE_YARA:
            try:
                self.native_rules = yara.compile(filepaths=yar_files)
                logger.info(f"Successfully compiled {len(yar_files)} YARA rule files via native yara-python.")
                return
            except Exception as e:
                logger.error(f"Native YARA compilation failed: {e}. Falling back to internal engine.")

        # Internal fallback engine
        self.fallback_rules = []
        for path in yar_files.values():
            self.fallback_rules.extend(parse_yar_file(path))
        logger.info(f"Loaded {len(self.fallback_rules)} YARA rules in universal engine.")

    def scan_bytes(self, file_bytes: bytes) -> List[Dict[str, Any]]:
        """Scans byte sequence safely without file execution and returns match details."""
        results: List[Dict[str, Any]] = []

        if HAS_NATIVE_YARA and self.native_rules is not None:
            try:
                matches = self.native_rules.match(data=file_bytes)
                for m in matches:
                    matched_strs = []
                    for s in getattr(m, "strings", []):
                        try:
                            # string format: (offset, identifier, data)
                            matched_strs.append(f"{s[1]}: {s[2].decode('utf-8', errors='ignore')}")
                        except Exception:
                            pass
                    results.append({
                        "rule_name": m.rule,
                        "tags": list(m.tags),
                        "meta": dict(m.meta),
                        "severity": m.meta.get("severity", "medium") if hasattr(m, "meta") else "medium",
                        "description": m.meta.get("description", f"Matched YARA rule: {m.rule}") if hasattr(m, "meta") else f"Matched {m.rule}",
                        "matched_strings": matched_strs
                    })
                return results
            except Exception as e:
                logger.error(f"Error during native YARA scan: {e}")

        # Universal engine execution
        for rule in self.fallback_rules:
            try:
                match_result = rule.match(file_bytes)
                if match_result:
                    results.append(match_result)
            except Exception as e:
                logger.debug(f"Error evaluating rule {rule.name}: {e}")

        return results


# Global singleton instance
yara_engine = ThreatLensYaraEngine()


def scan_file_with_yara(file_bytes: bytes) -> List[Dict[str, Any]]:
    """Public helper function to match file bytes against the active YARA rule set."""
    return yara_engine.scan_bytes(file_bytes)
