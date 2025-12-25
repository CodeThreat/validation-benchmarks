#!/usr/bin/env python3
"""
Benchmark Results Verification Script

This script verifies the accuracy of counting in the benchmark analysis results
to ensure no critical counting failures exist in the final numbers.

Verification Checks:
1. Sum consistency - benchmark-level sums match scanner-level totals
2. Vulnerability count consistency - same counts across scanners per benchmark
3. Rate calculation verification - mathematical correctness
4. Benchmark count verification - actual benchmarks match reported counts
5. Ground truth cross-check - rule files match reported vulnerability counts
"""

import json
from pathlib import Path
from collections import defaultdict
import re
import sys


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def load_json(filepath: Path) -> dict:
    """Load JSON file and return contents"""
    with open(filepath, 'r') as f:
        return json.load(f)


def count_rule_vulnerabilities(rules_dir: Path, max_benchmark: int = 51) -> dict:
    """
    Count vulnerabilities from rule files as ground truth.
    Returns dict: {benchmark_id: {'technical': count, 'non_technical': count}}
    """
    vuln_counts = {}
    
    for rule_file in rules_dir.glob("XBEN-*-000_vulns.json"):
        # Extract benchmark number
        match = re.search(r'XBEN-(\d{3})-', rule_file.name)
        if not match:
            continue
        
        benchmark_num = int(match.group(1))
        if benchmark_num > max_benchmark:
            continue
        
        benchmark_id = f"XBEN-{match.group(1)}"
        
        with open(rule_file, 'r') as f:
            data = json.load(f)
        
        if 'vulnerabilities' not in data:
            continue
        
        technical = sum(1 for v in data['vulnerabilities'] if v.get('is_technical', False))
        non_technical = len(data['vulnerabilities']) - technical
        
        vuln_counts[benchmark_id] = {
            'technical': technical,
            'non_technical': non_technical,
            'total': len(data['vulnerabilities'])
        }
    
    return vuln_counts


def verify_sum_consistency(results: dict, result_type: str) -> list:
    """
    Verify that benchmark-level sums match scanner-level totals.
    result_type: 'detection' or 'false_positive'
    """
    errors = []
    metric_name = 'true_positives' if result_type == 'detection' else 'false_positives'
    
    for scanner, scanner_data in results.items():
        # Calculate sums from benchmark results
        bench_results = scanner_data.get('benchmark_results', {})
        
        tech_sum = sum(
            br.get('technical', {}).get(metric_name, 0) 
            for br in bench_results.values()
        )
        non_tech_sum = sum(
            br.get('non_technical', {}).get(metric_name, 0) 
            for br in bench_results.values()
        )
        findings_sum = sum(
            br.get('total_findings', 0) 
            for br in bench_results.values()
        )
        
        # Get reported totals
        reported_tech = scanner_data.get('technical', {}).get(metric_name, 0)
        reported_non_tech = scanner_data.get('non_technical', {}).get(metric_name, 0)
        reported_findings = scanner_data.get('total_findings', 0)
        
        # Check technical
        if tech_sum != reported_tech:
            errors.append({
                'scanner': scanner,
                'type': 'technical',
                'metric': metric_name,
                'calculated_sum': tech_sum,
                'reported': reported_tech,
                'difference': reported_tech - tech_sum
            })
        
        # Check non-technical
        if non_tech_sum != reported_non_tech:
            errors.append({
                'scanner': scanner,
                'type': 'non_technical',
                'metric': metric_name,
                'calculated_sum': non_tech_sum,
                'reported': reported_non_tech,
                'difference': reported_non_tech - non_tech_sum
            })
        
        # Check total findings
        if findings_sum != reported_findings:
            errors.append({
                'scanner': scanner,
                'type': 'total_findings',
                'metric': 'total_findings',
                'calculated_sum': findings_sum,
                'reported': reported_findings,
                'difference': reported_findings - findings_sum
            })
    
    return errors


def verify_vulnerability_counts_consistency(results: dict) -> list:
    """
    Verify that all scanners report the same total_known_vulnerabilities per benchmark.
    """
    errors = []
    
    # Collect vulnerability counts per benchmark across all scanners
    benchmark_counts = defaultdict(dict)
    
    for scanner, scanner_data in results.items():
        for bench_id, bench_data in scanner_data.get('benchmark_results', {}).items():
            tech_vulns = bench_data.get('technical', {}).get('total_known_vulnerabilities', 0)
            non_tech_vulns = bench_data.get('non_technical', {}).get('total_known_vulnerabilities', 0)
            
            if bench_id not in benchmark_counts:
                benchmark_counts[bench_id] = {
                    'technical': {},
                    'non_technical': {}
                }
            
            benchmark_counts[bench_id]['technical'][scanner] = tech_vulns
            benchmark_counts[bench_id]['non_technical'][scanner] = non_tech_vulns
    
    # Check for inconsistencies
    for bench_id, counts in benchmark_counts.items():
        for vuln_type in ['technical', 'non_technical']:
            values = list(counts[vuln_type].values())
            if len(set(values)) > 1:
                errors.append({
                    'benchmark': bench_id,
                    'type': vuln_type,
                    'scanner_values': counts[vuln_type],
                    'issue': 'Inconsistent vulnerability counts across scanners'
                })
    
    return errors


def verify_rate_calculations(results: dict, result_type: str) -> list:
    """
    Verify that rate calculations are mathematically correct.
    result_type: 'detection' or 'false_positive'
    """
    errors = []
    metric_name = 'true_positives' if result_type == 'detection' else 'false_positives'
    rate_name = 'detection_rate' if result_type == 'detection' else 'false_positive_rate'
    
    for scanner, scanner_data in results.items():
        # Check scanner-level rates
        for vuln_type in ['technical', 'non_technical']:
            type_data = scanner_data.get(vuln_type, {})
            count = type_data.get(metric_name, 0)
            total = type_data.get('total_known_vulnerabilities', 0)
            reported_rate = type_data.get(rate_name, 0)
            
            if total > 0:
                expected_rate = (count / total) * 100
                # Allow small floating point differences
                if abs(expected_rate - reported_rate) > 0.01:
                    errors.append({
                        'scanner': scanner,
                        'level': 'scanner',
                        'type': vuln_type,
                        'count': count,
                        'total': total,
                        'expected_rate': expected_rate,
                        'reported_rate': reported_rate,
                        'difference': reported_rate - expected_rate
                    })
        
        # Check benchmark-level rates
        for bench_id, bench_data in scanner_data.get('benchmark_results', {}).items():
            for vuln_type in ['technical', 'non_technical']:
                type_data = bench_data.get(vuln_type, {})
                count = type_data.get(metric_name, 0)
                total = type_data.get('total_known_vulnerabilities', 0)
                reported_rate = type_data.get(rate_name, 0)
                
                if total > 0:
                    expected_rate = (count / total) * 100
                    if abs(expected_rate - reported_rate) > 0.01:
                        errors.append({
                            'scanner': scanner,
                            'level': 'benchmark',
                            'benchmark': bench_id,
                            'type': vuln_type,
                            'count': count,
                            'total': total,
                            'expected_rate': expected_rate,
                            'reported_rate': reported_rate,
                            'difference': reported_rate - expected_rate
                        })
    
    return errors


def verify_benchmark_counts(results: dict, benchmarks_dir: Path, expected_count: int) -> dict:
    """
    Verify that the number of scanned benchmarks matches expected.
    """
    result = {
        'expected': expected_count,
        'reported': {},
        'actual_dirs': 0,
        'errors': []
    }
    
    # Count actual benchmark directories (excluding unported)
    actual_benchmarks = set()
    for d in benchmarks_dir.iterdir():
        if d.is_dir() and d.name.startswith('XBEN-') and d.name != 'unported':
            match = re.search(r'XBEN-(\d{3})-', d.name)
            if match and int(match.group(1)) <= 51:
                actual_benchmarks.add(f"XBEN-{match.group(1)}")
    
    result['actual_dirs'] = len(actual_benchmarks)
    
    # Check reported counts per scanner
    for scanner, scanner_data in results.items():
        reported = scanner_data.get('scanned_benchmarks', 0)
        result['reported'][scanner] = reported
        
        if reported != expected_count:
            result['errors'].append({
                'scanner': scanner,
                'reported': reported,
                'expected': expected_count
            })
    
    return result


def verify_ground_truth(results: dict, rule_vuln_counts: dict) -> list:
    """
    Cross-check that reported vulnerability counts match rule file counts.
    """
    errors = []
    
    for scanner, scanner_data in results.items():
        for bench_id, bench_data in scanner_data.get('benchmark_results', {}).items():
            if bench_id not in rule_vuln_counts:
                errors.append({
                    'scanner': scanner,
                    'benchmark': bench_id,
                    'issue': 'Benchmark has results but no rule file found'
                })
                continue
            
            ground_truth = rule_vuln_counts[bench_id]
            
            for vuln_type in ['technical', 'non_technical']:
                reported = bench_data.get(vuln_type, {}).get('total_known_vulnerabilities', 0)
                expected = ground_truth[vuln_type]
                
                if reported != expected:
                    errors.append({
                        'scanner': scanner,
                        'benchmark': bench_id,
                        'type': vuln_type,
                        'reported': reported,
                        'ground_truth': expected,
                        'difference': reported - expected
                    })
    
    return errors


def calculate_totals(results: dict, result_type: str) -> dict:
    """Calculate aggregate totals across all scanners."""
    metric_name = 'true_positives' if result_type == 'detection' else 'false_positives'
    
    totals = {}
    for scanner, scanner_data in results.items():
        totals[scanner] = {
            'technical': scanner_data.get('technical', {}).get(metric_name, 0),
            'non_technical': scanner_data.get('non_technical', {}).get(metric_name, 0),
            'total_findings': scanner_data.get('total_findings', 0),
            'tech_total_vulns': scanner_data.get('technical', {}).get('total_known_vulnerabilities', 0),
            'non_tech_total_vulns': scanner_data.get('non_technical', {}).get('total_known_vulnerabilities', 0)
        }
    return totals


def print_section(title: str):
    """Print a section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")


def print_result(check_name: str, passed: bool, details: str = ""):
    """Print a verification result"""
    status = f"{Colors.GREEN}PASS{Colors.END}" if passed else f"{Colors.RED}FAIL{Colors.END}"
    print(f"  [{status}] {check_name}")
    if details:
        print(f"         {details}")


def main():
    # Paths
    project_root = Path(__file__).parent.parent
    results_dir = project_root / "results"
    rules_dir = project_root / "rules"
    benchmarks_dir = project_root / "benchmarks"
    benchmarks_patched_dir = project_root / "benchmarks_patched"
    
    detection_file = results_dir / "scanner_performance_summary_detection_rates.json"
    fp_file = results_dir / "scanner_performance_summary_technical_false_positives.json"
    
    print(f"{Colors.BOLD}Benchmark Results Verification{Colors.END}")
    print(f"{'='*60}")
    
    # Load data
    print("\nLoading data...")
    detection_data = load_json(detection_file)
    fp_data = load_json(fp_file)
    rule_vulns = count_rule_vulnerabilities(rules_dir)
    
    detection_results = detection_data.get('results', {})
    fp_results = fp_data.get('results', {})
    
    print(f"  Detection rates file: {len(detection_results)} scanners")
    print(f"  False positive file: {len(fp_results)} scanners")
    print(f"  Rule files loaded: {len(rule_vulns)} benchmarks")
    
    all_errors = []
    
    # =========================================================================
    # Check 1: Sum Consistency
    # =========================================================================
    print_section("1. SUM CONSISTENCY VERIFICATION")
    
    print("\n  Detection Rates:")
    det_sum_errors = verify_sum_consistency(detection_results, 'detection')
    if det_sum_errors:
        all_errors.extend(det_sum_errors)
        for err in det_sum_errors:
            print_result(
                f"{err['scanner']} - {err['type']}",
                False,
                f"Calculated: {err['calculated_sum']}, Reported: {err['reported']}, Diff: {err['difference']}"
            )
    else:
        print_result("All scanner sums match benchmark totals", True)
    
    print("\n  False Positives:")
    fp_sum_errors = verify_sum_consistency(fp_results, 'false_positive')
    if fp_sum_errors:
        all_errors.extend(fp_sum_errors)
        for err in fp_sum_errors:
            print_result(
                f"{err['scanner']} - {err['type']}",
                False,
                f"Calculated: {err['calculated_sum']}, Reported: {err['reported']}, Diff: {err['difference']}"
            )
    else:
        print_result("All scanner sums match benchmark totals", True)
    
    # =========================================================================
    # Check 2: Vulnerability Count Consistency
    # =========================================================================
    print_section("2. VULNERABILITY COUNT CONSISTENCY")
    
    print("\n  Detection Rates:")
    det_vuln_errors = verify_vulnerability_counts_consistency(detection_results)
    if det_vuln_errors:
        all_errors.extend(det_vuln_errors)
        for err in det_vuln_errors:
            print_result(
                f"{err['benchmark']} - {err['type']}",
                False,
                f"Values: {err['scanner_values']}"
            )
    else:
        print_result("All scanners report consistent vulnerability counts", True)
    
    print("\n  False Positives:")
    fp_vuln_errors = verify_vulnerability_counts_consistency(fp_results)
    if fp_vuln_errors:
        all_errors.extend(fp_vuln_errors)
        for err in fp_vuln_errors:
            print_result(
                f"{err['benchmark']} - {err['type']}",
                False,
                f"Values: {err['scanner_values']}"
            )
    else:
        print_result("All scanners report consistent vulnerability counts", True)
    
    # =========================================================================
    # Check 3: Rate Calculations
    # =========================================================================
    print_section("3. RATE CALCULATION VERIFICATION")
    
    print("\n  Detection Rates:")
    det_rate_errors = verify_rate_calculations(detection_results, 'detection')
    if det_rate_errors:
        all_errors.extend(det_rate_errors)
        for err in det_rate_errors[:5]:  # Show first 5
            location = err.get('benchmark', 'scanner-level')
            print_result(
                f"{err['scanner']} - {err['type']} ({location})",
                False,
                f"Expected: {err['expected_rate']:.4f}, Reported: {err['reported_rate']:.4f}"
            )
        if len(det_rate_errors) > 5:
            print(f"         ... and {len(det_rate_errors) - 5} more rate errors")
    else:
        print_result("All detection rate calculations are correct", True)
    
    print("\n  False Positive Rates:")
    fp_rate_errors = verify_rate_calculations(fp_results, 'false_positive')
    if fp_rate_errors:
        all_errors.extend(fp_rate_errors)
        for err in fp_rate_errors[:5]:
            location = err.get('benchmark', 'scanner-level')
            print_result(
                f"{err['scanner']} - {err['type']} ({location})",
                False,
                f"Expected: {err['expected_rate']:.4f}, Reported: {err['reported_rate']:.4f}"
            )
        if len(fp_rate_errors) > 5:
            print(f"         ... and {len(fp_rate_errors) - 5} more rate errors")
    else:
        print_result("All false positive rate calculations are correct", True)
    
    # =========================================================================
    # Check 4: Benchmark Counts
    # =========================================================================
    print_section("4. BENCHMARK COUNT VERIFICATION")
    
    print("\n  Detection Rates (expected: 39 benchmarks):")
    det_bench_check = verify_benchmark_counts(detection_results, benchmarks_dir, 39)
    if det_bench_check['errors']:
        all_errors.extend(det_bench_check['errors'])
        for err in det_bench_check['errors']:
            print_result(
                f"{err['scanner']}",
                False,
                f"Reported: {err['reported']}, Expected: {err['expected']}"
            )
    else:
        print_result("All scanners report 39 benchmarks", True)
    print(f"         Actual benchmark directories found: {det_bench_check['actual_dirs']}")
    
    print("\n  False Positives (expected: 23 benchmarks):")
    fp_bench_check = verify_benchmark_counts(fp_results, benchmarks_patched_dir, 23)
    if fp_bench_check['errors']:
        all_errors.extend(fp_bench_check['errors'])
        for err in fp_bench_check['errors']:
            print_result(
                f"{err['scanner']}",
                False,
                f"Reported: {err['reported']}, Expected: {err['expected']}"
            )
    else:
        print_result("All scanners report 23 benchmarks", True)
    print(f"         Actual benchmark directories found: {fp_bench_check['actual_dirs']}")
    
    # =========================================================================
    # Check 5: Ground Truth Cross-Check
    # =========================================================================
    print_section("5. GROUND TRUTH CROSS-CHECK")
    
    print("\n  Detection Rates:")
    det_gt_errors = verify_ground_truth(detection_results, rule_vulns)
    if det_gt_errors:
        all_errors.extend(det_gt_errors)
        # Group by issue type
        missing_rules = [e for e in det_gt_errors if 'rule file' in e.get('issue', '')]
        count_mismatches = [e for e in det_gt_errors if 'difference' in e]
        
        if missing_rules:
            print_result(
                f"Missing rule files",
                False,
                f"{len(missing_rules)} benchmarks have no rule files"
            )
        if count_mismatches:
            for err in count_mismatches[:5]:
                print_result(
                    f"{err['benchmark']} - {err['type']}",
                    False,
                    f"Reported: {err['reported']}, Ground truth: {err['ground_truth']}"
                )
            if len(count_mismatches) > 5:
                print(f"         ... and {len(count_mismatches) - 5} more mismatches")
    else:
        print_result("All vulnerability counts match rule files", True)
    
    print("\n  False Positives:")
    fp_gt_errors = verify_ground_truth(fp_results, rule_vulns)
    if fp_gt_errors:
        all_errors.extend(fp_gt_errors)
        missing_rules = [e for e in fp_gt_errors if 'rule file' in e.get('issue', '')]
        count_mismatches = [e for e in fp_gt_errors if 'difference' in e]
        
        if missing_rules:
            print_result(
                f"Missing rule files",
                False,
                f"{len(missing_rules)} benchmarks have no rule files"
            )
        if count_mismatches:
            for err in count_mismatches[:5]:
                print_result(
                    f"{err['benchmark']} - {err['type']}",
                    False,
                    f"Reported: {err['reported']}, Ground truth: {err['ground_truth']}"
                )
            if len(count_mismatches) > 5:
                print(f"         ... and {len(count_mismatches) - 5} more mismatches")
    else:
        print_result("All vulnerability counts match rule files", True)
    
    # =========================================================================
    # Summary
    # =========================================================================
    print_section("VERIFICATION SUMMARY")
    
    # Print totals for detection rates
    print("\n  Detection Rates Summary:")
    det_totals = calculate_totals(detection_results, 'detection')
    print(f"  {'Scanner':<15} {'Tech TP':>10} {'Non-Tech TP':>12} {'Total Findings':>15}")
    print(f"  {'-'*52}")
    for scanner, totals in det_totals.items():
        print(f"  {scanner:<15} {totals['technical']:>10} {totals['non_technical']:>12} {totals['total_findings']:>15}")
    
    # Calculate expected totals from ground truth for scanned benchmarks
    det_bench_ids = set()
    for scanner_data in detection_results.values():
        det_bench_ids.update(scanner_data.get('benchmark_results', {}).keys())
    
    total_tech_vulns = sum(rule_vulns.get(b, {}).get('technical', 0) for b in det_bench_ids)
    total_non_tech_vulns = sum(rule_vulns.get(b, {}).get('non_technical', 0) for b in det_bench_ids)
    print(f"\n  Ground truth totals for {len(det_bench_ids)} benchmarks:")
    print(f"    Technical vulnerabilities: {total_tech_vulns}")
    print(f"    Non-technical vulnerabilities: {total_non_tech_vulns}")
    print(f"    Total: {total_tech_vulns + total_non_tech_vulns}")
    
    # Print totals for false positives
    print("\n  False Positive Summary:")
    fp_totals = calculate_totals(fp_results, 'false_positive')
    print(f"  {'Scanner':<15} {'Tech FP':>10} {'Non-Tech FP':>12} {'Total Findings':>15}")
    print(f"  {'-'*52}")
    for scanner, totals in fp_totals.items():
        print(f"  {scanner:<15} {totals['technical']:>10} {totals['non_technical']:>12} {totals['total_findings']:>15}")
    
    # Final status
    print(f"\n{Colors.BOLD}FINAL RESULT:{Colors.END}")
    if all_errors:
        print(f"  {Colors.RED}VERIFICATION FAILED{Colors.END}")
        print(f"  Total issues found: {len(all_errors)}")
        
        # Categorize errors
        sum_errors = [e for e in all_errors if 'calculated_sum' in e]
        consistency_errors = [e for e in all_errors if 'scanner_values' in e]
        rate_errors = [e for e in all_errors if 'expected_rate' in e]
        bench_errors = [e for e in all_errors if 'reported' in e and 'expected' in e and 'ground_truth' not in e]
        gt_errors = [e for e in all_errors if 'ground_truth' in e or 'rule file' in e.get('issue', '')]
        
        print(f"    - Sum consistency issues: {len(sum_errors)}")
        print(f"    - Vulnerability count consistency issues: {len(consistency_errors)}")
        print(f"    - Rate calculation issues: {len(rate_errors)}")
        print(f"    - Benchmark count issues: {len(bench_errors)}")
        print(f"    - Ground truth mismatches: {len(gt_errors)}")
        
        return 1
    else:
        print(f"  {Colors.GREEN}ALL VERIFICATION CHECKS PASSED{Colors.END}")
        print("  No critical counting failures detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

