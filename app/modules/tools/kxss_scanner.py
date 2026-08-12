import asyncio
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Callable, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import pandas as pd

logger = logging.getLogger(__name__)

# kxss output parsing regex
# Example: https://example.com/?q=FUZZ Param: q Unfiltered: [$ | ( ) ` : ; { }]
KXSS_PATTERN = re.compile(
    r"^(?P<url>https?://[^\s]+)\s+Param:\s+(?P<param>[^\s]+)\s+Unfiltered:\s+\[(?P<unfiltered>[^\]]*)\]"
)

# Characters that indicate good XSS potential (from kxss output)
HIGH_VALUE_CHARS = set(['<', '>', '"', "'", '(', ')', '{', '}', '`', ';', ':', '|'])


class KXSSScanner:
    """
    Async wrapper around Emoe's kxss Go binary.

    Pipeline: GF flags XSS candidates -> kxss probes for reflection ->
    Parse output for unfiltered characters -> Score severity -> Report
    """

    def __init__(self, config: Dict):
        self.config = config
        self.kxss_path = Path(config.get('tools', {}).get('paths', {}).get('kxss', 'kxss'))
        self.timeout = config.get('tools', {}).get('timeouts', {}).get('kxss', 300)
        self.max_concurrent = config.get('tools', {}).get('concurrency', {}).get('kxss', 10)

        if not self.kxss_path.is_file():
            logger.warning(f"kxss binary not found at {self.kxss_path}. "
                          f"Install with: go install github.com/Emoe/kxss@latest")

    async def _run_kxss_on_urls(self, urls: List[str], semaphore: asyncio.Semaphore) -> List[Dict]:
        """
        Run kxss on a batch of URLs via stdin.
        kxss reads URLs from stdin and outputs findings to stdout.
        """
        if not self.kxss_path.is_file():
            logger.error("kxss binary not found. Skipping.")
            return []

        if not urls:
            return []

        async with semaphore:
            # kxss reads URLs from stdin, one per line
            stdin_data = "\n".join(urls) + "\n"

            try:
                proc = await asyncio.create_subprocess_exec(
                    str(self.kxss_path),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=stdin_data.encode()),
                    timeout=self.timeout
                )

                if stderr:
                    logger.debug(f"kxss stderr: {stderr.decode('utf-8', errors='ignore')}")

                return self._parse_kxss_output(stdout.decode('utf-8', errors='ignore'))

            except asyncio.TimeoutError:
                logger.warning(f"kxss timed out after {self.timeout}s for batch of {len(urls)} URLs")
                proc.kill()
                await proc.wait()
                return []
            except Exception as e:
                logger.error(f"kxss execution failed: {e}")
                return []

    def _parse_kxss_output(self, output: str) -> List[Dict]:
        """
        Parse kxss stdout into structured findings.

        Output format per line:
        https://target.com/?q=FUZZ Param: q Unfiltered: [$ | ( ) ` : ; { }]
        """
        findings = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            match = KXSS_PATTERN.match(line)
            if match:
                url = match.group('url')
                param = match.group('param')
                unfiltered_raw = match.group('unfiltered').strip()

                # Parse unfiltered characters
                unfiltered_chars = [c.strip() for c in unfiltered_raw.split() if c.strip()]

                # Calculate severity based on unfiltered characters
                severity = self._calculate_severity(unfiltered_chars, param)

                findings.append({
                    'url': url,
                    'parameter': param,
                    'unfiltered_chars': unfiltered_chars,
                    'unfiltered_raw': unfiltered_raw,
                    'severity': severity['level'],
                    'severity_score': severity['score'],
                    'context': severity['context'],
                    'confidence': severity['confidence'],
                    'payload_suggestion': severity['payload'],
                    'note': severity['note'],
                })
            else:
                # Some lines might be just the URL without match (no reflection)
                if line.startswith('http'):
                    logger.debug(f"kxss: No reflection found for {line[:80]}...")

        return findings

    def _calculate_severity(self, unfiltered_chars: List[str], param: str) -> Dict:
        """
        Score the XSS potential based on unfiltered characters.
        Returns severity dict with level, score, context, and payload suggestion.
        """
        chars_set = set(unfiltered_chars)
        score = 0
        context = []
        payloads = []
        notes = []

        # HTML context indicators
        if '<' in chars_set and '>' in chars_set:
            score += 40
            context.append("HTML injection")
            payloads.append(f"<{param}>")

        if '"' in chars_set:
            score += 25
            context.append("Attribute break-out")
            payloads.append('\">')

        if "'" in chars_set:
            score += 25
            context.append("Single-quote attribute")
            payloads.append("'>")

        if '(' in chars_set and ')' in chars_set:
            score += 20
            context.append("JavaScript execution")
            payloads.append("javascript:alert(1)")

        if '`' in chars_set:
            score += 20
            context.append("Template literal injection")
            payloads.append("`${alert(1)}`")

        if '{' in chars_set and '}' in chars_set:
            score += 15
            context.append("Object/Template syntax")

        if ';' in chars_set:
            score += 10
            context.append("Statement terminator")

        if ':' in chars_set:
            score += 10
            context.append("Protocol/Expression separator")

        # Special case: completely unfiltered (empty unfiltered list but param reflected)
        if not unfiltered_chars:
            score += 5
            notes.append("Parameter reflected but no special chars tested")

        # Determine severity level
        if score >= 70:
            level = "CRITICAL"
            confidence = "High"
        elif score >= 45:
            level = "HIGH"
            confidence = "High"
        elif score >= 25:
            level = "MEDIUM"
            confidence = "Medium"
        elif score > 0:
            level = "LOW"
            confidence = "Low"
        else:
            level = "INFO"
            confidence = "Very Low"

        # Build payload suggestion
        if payloads:
            payload = " | ".join(payloads[:3])
        else:
            payload = f"{param}=test (basic reflection, minimal chars)"

        note = "; ".join(notes) if notes else f"Context: {', '.join(context)}" if context else "Basic parameter reflection"

        return {
            'level': level,
            'score': score,
            'context': ', '.join(context) if context else 'Unknown',
            'confidence': confidence,
            'payload': payload,
            'note': note,
        }

    async def probe_xss_candidates(self, 
                                    urls: List[str],
                                    progress_callback: Optional[Callable[[float, str], None]] = None
                                   ) -> pd.DataFrame:
        """
        Main entry point: Probe URLs for XSS reflection using kxss.

        Args:
            urls: List of URLs with parameters (typically from GF xss pattern matches)
            progress_callback: Optional callback(progress_float, message)

        Returns:
            DataFrame with confirmed XSS findings
        """
        if not urls:
            logger.info("No URLs provided for kxss probing.")
            return pd.DataFrame()

        if not self.kxss_path.is_file():
            logger.error("kxss binary not available. Install: go install github.com/Emoe/kxss@latest")
            return pd.DataFrame()

        # Deduplicate URLs
        unique_urls = list(dict.fromkeys(urls))
        total = len(unique_urls)
        logger.info(f"Probing {total} URLs with kxss...")

        if progress_callback:
            progress_callback(0.0, f"Preparing {total} URLs for kxss probing...")

        # kxss works best with smaller batches to avoid stdin buffer issues
        batch_size = 50
        batches = [unique_urls[i:i + batch_size] for i in range(0, total, batch_size)]

        semaphore = asyncio.Semaphore(self.max_concurrent)
        all_findings = []
        processed = 0

        for batch_idx, batch in enumerate(batches):
            if progress_callback:
                progress = (batch_idx / len(batches)) * 0.9
                progress_callback(progress, f"Probing batch {batch_idx + 1}/{len(batches)} ({len(batch)} URLs)...")

            findings = await self._run_kxss_on_urls(batch, semaphore)
            all_findings.extend(findings)
            processed += len(batch)

            logger.info(f"Batch {batch_idx + 1}/{len(batches)}: {len(findings)} reflections found")

        if progress_callback:
            progress_callback(0.95, "Consolidating results...")

        if not all_findings:
            logger.info("kxss found no reflected parameters.")
            if progress_callback:
                progress_callback(1.0, "No XSS reflections found.")
            return pd.DataFrame()

        # Build DataFrame
        df = pd.DataFrame(all_findings)

        # Sort by severity score descending
        df = df.sort_values('severity_score', ascending=False).reset_index(drop=True)

        # Add a column for quick triage
        df['triage'] = df.apply(self._triage_finding, axis=1)

        if progress_callback:
            critical_count = len(df[df['severity'] == 'CRITICAL'])
            high_count = len(df[df['severity'] == 'HIGH'])
            progress_callback(1.0, f"Done! {len(df)} reflections: {critical_count} CRITICAL, {high_count} HIGH")

        logger.info(f"kxss complete: {len(df)} findings ({len(df[df['severity'] == 'CRITICAL'])} CRITICAL)")
        return df

    def _triage_finding(self, row) -> str:
        """Generate a quick triage label for a finding."""
        if row['severity'] == 'CRITICAL':
            return "🚨 IMMEDIATE TRIAGE"
        elif row['severity'] == 'HIGH':
            return "🔥 HIGH PRIORITY"
        elif row['severity'] == 'MEDIUM':
            return "⚠️ WORTH TESTING"
        else:
            return "📋 LOW PRIORITY"

    # ----- Synchronous wrapper for Streamlit -----
    def probe_xss_candidates_sync(self, 
                                   urls: List[str],
                                   progress_callback: Optional[Callable[[float, str], None]] = None
                                  ) -> pd.DataFrame:
        """Synchronous entry point for Streamlit."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
            return asyncio.run(self.probe_xss_candidates(urls, progress_callback))
        else:
            return asyncio.run(self.probe_xss_candidates(urls, progress_callback))