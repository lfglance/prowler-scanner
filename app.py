#!/usr/bin/env python3

import aws_cdk as cdk
from prowler_scan_automation.prowler_scanner import ProwlerScanner


app = cdk.App()
scanner = ProwlerScanner(app, "ProwlerScannerStack")
app.synth()
