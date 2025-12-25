import os
from pathlib import Path
import subprocess
import logging
import shutil

# Configure logging early (before any logging calls)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Load .env file from project root
    project_root = Path(__file__).parent.parent
    env_file = project_root / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        logging.info(f"Loaded environment variables from {env_file}")
except ImportError:
    # python-dotenv not installed, will use environment variables only
    pass
except Exception as e:
    logging.warning(f"Could not load .env file: {e}")

def backup_sarif_files(dir_path: Path, temp_base: Path) -> Path:
    """
    Backup existing SARIF files to a temporary directory and remove them from the benchmark directory.
    This ensures scanners don't see existing SARIF files.
    
    Args:
        dir_path: Benchmark directory containing SARIF files
        temp_base: Base temporary directory (e.g., /temps)
    
    Returns:
        Path to the temporary backup directory for this benchmark
    """
    temp_backup_dir = temp_base / dir_path.name
    temp_backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all SARIF files in the benchmark directory
    sarif_files = list(dir_path.glob("*_raw.sarif"))
    
    backed_up_files = []
    for sarif_file in sarif_files:
        backup_path = temp_backup_dir / sarif_file.name
        try:
            # Copy to backup
            shutil.copy2(sarif_file, backup_path)
            # Remove from benchmark directory
            sarif_file.unlink()
            backed_up_files.append(sarif_file.name)
            logging.info(f"Backed up and removed {sarif_file.name}")
        except Exception as e:
            logging.warning(f"Failed to backup/remove {sarif_file.name}: {e}")
    
    if backed_up_files:
        logging.info(f"Backed up and removed {len(backed_up_files)} SARIF file(s) for {dir_path.name}")
    else:
        logging.info(f"No existing SARIF files to backup for {dir_path.name}")
    
    return temp_backup_dir

def restore_sarif_files(dir_path: Path, temp_backup_dir: Path):
    """
    Restore SARIF files from temporary backup directory.
    Only restores files that don't exist in the target directory (to preserve new scan results).
    
    Args:
        dir_path: Benchmark directory to restore SARIF files to
        temp_backup_dir: Temporary backup directory containing SARIF files
    """
    if not temp_backup_dir.exists():
        logging.warning(f"Backup directory does not exist: {temp_backup_dir}")
        return
    
    # Find all SARIF files in the backup directory
    backup_sarif_files = list(temp_backup_dir.glob("*_raw.sarif"))
    
    restored_files = []
    skipped_files = []
    for backup_file in backup_sarif_files:
        restore_path = dir_path / backup_file.name
        
        # Only restore if file doesn't exist (new scan may have created it)
        if restore_path.exists():
            skipped_files.append(backup_file.name)
            logging.debug(f"Skipping restore of {backup_file.name} - file exists (preserving new scan result)")
            continue
        
        try:
            shutil.copy2(backup_file, restore_path)
            restored_files.append(backup_file.name)
            logging.info(f"Restored {backup_file.name} to {restore_path}")
        except Exception as e:
            logging.warning(f"Failed to restore {backup_file.name}: {e}")
    
    if restored_files:
        logging.info(f"Restored {len(restored_files)} SARIF file(s) for {dir_path.name}")
    if skipped_files:
        logging.info(f"Preserved {len(skipped_files)} new SARIF file(s) from scan (skipped restore)")
    if not restored_files and not skipped_files:
        logging.info(f"No SARIF files to restore for {dir_path.name}")

def run_sast_scan(subdir, skip_existing_scanners=True):
    """
    Run SAST scans for a given directory using Snyk, Bearer, Semgrep, ZeroPath, and CodeThreat Hive.
    
    Args:
        subdir: Directory to scan
        skip_existing_scanners: If True, skip scanners that already have SARIF files (default: True)
    """
    # Create Path object for better path handling
    dir_path = Path(subdir).resolve()  # Get absolute path
    
    # Create temp directory for backups
    project_root = Path(__file__).parent.parent
    temp_base = project_root / "temps"
    
    # Backup existing SARIF files before scanning
    temp_backup_dir = None
    try:
        temp_backup_dir = backup_sarif_files(dir_path, temp_base)
        
        logging.info(f"Starting scan for directory: {dir_path}")
        
        # Check if other scanners already have SARIF files
        other_scanners_complete = False
        if skip_existing_scanners:
            existing_sarifs = [
                dir_path / "snyk_code_raw.sarif",
                dir_path / "semgrep_raw.sarif",
                dir_path / "bearer_raw.sarif",
                dir_path / "zeropath_raw.sarif"
            ]
            if all(sarif.exists() for sarif in existing_sarifs):
                other_scanners_complete = True
                logging.info(f"All other scanners already have SARIF files. Skipping Snyk, Semgrep, Bearer, and ZeroPath.")
        
        # Run Snyk code scan
        if not other_scanners_complete:
            snyk_sarif = dir_path / "snyk_code_raw.sarif"
            if not snyk_sarif.exists():
                snyk_cmd = [
                    "snyk", "code", "test",
                    str(dir_path),
                    "--sarif-file-output=" + str(snyk_sarif)
                ]
                logging.info(f"Running Snyk command: {' '.join(snyk_cmd)}")
                try:
                    snyk_result = subprocess.run(
                        snyk_cmd, 
                        capture_output=True, 
                        text=True,
                        check=False
                    )
                    logging.info(f"Snyk exit code: {snyk_result.returncode}")
                    if snyk_result.returncode != 0:
                        logging.warning(f"Snyk warnings/errors: {snyk_result.stderr} {snyk_result.stdout}")
                except Exception as e:
                    logging.error(f"Error running Snyk: {str(e)}")
            else:
                logging.info(f"Skipping Snyk scan - SARIF file already exists: {snyk_sarif}")

        # Run Bearer code scan
        if not other_scanners_complete:
            bearer_sarif = dir_path / "bearer_raw.sarif"
            if not bearer_sarif.exists():
                bearer_cmd = [
                    "bearer", "scan", 
                    str(dir_path),
                    "-f", "sarif",
                    "--output", str(bearer_sarif)
                ]
                logging.info(f"Running Bearer command: {' '.join(bearer_cmd)}")
                try:
                    bearer_result = subprocess.run(
                        bearer_cmd, 
                        capture_output=True, 
                        text=True,
                        check=False
                    )
                    logging.info(f"Bearer exit code: {bearer_result.returncode}")
                    if bearer_result.returncode != 0:
                        logging.warning(f"Bearer warnings/errors: {bearer_result.stderr} {bearer_result.stdout}")
                except Exception as e:
                    logging.error(f"Error running Bearer: {str(e)}")
            else:
                logging.info(f"Skipping Bearer scan - SARIF file already exists: {bearer_sarif}")

        # Run Semgrep scan
        if not other_scanners_complete:
            semgrep_sarif = dir_path / "semgrep_raw.sarif"
            if not semgrep_sarif.exists():
                semgrep_cmd = [
                    "semgrep", "scan",
                    str(dir_path),
                    "--config=auto",
                    "--sarif",
                    "--output", str(semgrep_sarif)
                ]
                logging.info(f"Running Semgrep command: {' '.join(semgrep_cmd)}")
                
                # Change to the target directory before running semgrep
                original_dir = os.getcwd()
                os.chdir(str(dir_path))
                
                try:
                    semgrep_result = subprocess.run(
                        semgrep_cmd,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    logging.info(f"Semgrep exit code: {semgrep_result.returncode}")
                    
                    # Log Semgrep output
                    if semgrep_result.stdout:
                        logging.info(f"Semgrep stdout: {semgrep_result.stdout}")
                    if semgrep_result.stderr:
                        logging.warning(f"Semgrep stderr: {semgrep_result.stderr}")
                        
                    # Check if SARIF file was created
                    if semgrep_sarif.exists():
                        logging.info(f"Semgrep SARIF file created: {semgrep_sarif}")
                        with open(semgrep_sarif, 'r') as f:
                            file_size = len(f.read())
                            logging.info(f"SARIF file size: {file_size} bytes")
                    else:
                        logging.error(f"Semgrep SARIF file not created at: {semgrep_sarif}")
                        
                except Exception as e:
                    logging.error(f"Error running Semgrep: {str(e)}")
                finally:
                    # Return to original directory
                    os.chdir(original_dir)
            else:
                logging.info(f"Skipping Semgrep scan - SARIF file already exists: {semgrep_sarif}")

        # Run ZeroPath scan
        if not other_scanners_complete:
            zeropath_sarif = dir_path / "zeropath_raw.sarif"
            if not zeropath_sarif.exists():
                zeropath_cmd = [
                    "zeropath",
                    "scan",
                    str(dir_path),
                    str(zeropath_sarif)
                ]
                
                print("zeropath cli", " ".join(zeropath_cmd))
                # Set up environment for ZeroPath
                zeropath_env = os.environ.copy()
                # external users should comment this out, this is our pre-staging env
                #zeropath_env["ZEROPATH_ENVIRONMENT"] = "https://raphael.branch.zeropath.com"
                
                logging.info(f"Running ZeroPath command: {' '.join(zeropath_cmd)}")
                try:
                    zeropath_result = subprocess.run(
                        zeropath_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                        env=zeropath_env
                    )
                    logging.info(f"ZeroPath exit code: {zeropath_result.returncode}")
                    
                    # Log ZeroPath output
                    if zeropath_result.stdout:
                        logging.info(f"ZeroPath stdout: {zeropath_result.stdout}")
                    if zeropath_result.stderr:
                        logging.warning(f"ZeroPath stderr: {zeropath_result.stderr}")
                        
                    # Check if SARIF file was created
                    if zeropath_sarif.exists():
                        logging.info(f"ZeroPath SARIF file created: {zeropath_sarif}")
                        with open(zeropath_sarif, 'r') as f:
                            file_size = len(f.read())
                            logging.info(f"SARIF file size: {file_size} bytes")
                    else:
                        logging.error(f"ZeroPath SARIF file not created at: {zeropath_sarif}")
                        
                except Exception as e:
                    logging.error(f"Error running ZeroPath: {str(e)}")
            else:
                logging.info(f"Skipping ZeroPath scan - SARIF file already exists: {zeropath_sarif}")

        # Run CodeThreat Hive scan
        cthive_sarif = dir_path / "cthive_raw.sarif"
        if not cthive_sarif.exists():
            # CodeThreat Hive must run from its project root (where .env is located)
            cthive_root = os.environ.get("CODETHREAT_HIVE_ROOT")
            if not cthive_root:
                logging.warning("CODETHREAT_HIVE_ROOT environment variable not set. Skipping CodeThreat Hive scan.")
                logging.warning("Set CODETHREAT_HIVE_ROOT to the path of CodeThreat Hive project root (where .env is located)")
            else:
                cthive_root_path = Path(cthive_root).resolve()
                if not cthive_root_path.exists():
                    logging.error(f"CodeThreat Hive root directory does not exist: {cthive_root_path}")
                elif not (cthive_root_path / ".env").exists():
                    logging.warning(f".env file not found in CodeThreat Hive root: {cthive_root_path}")
                    logging.warning("CodeThreat Hive requires .env file for LLM provider configuration")
                else:
                    cthive_cmd = [
                        "python3", "-m", "hive", "security",
                        "--path", str(dir_path),  # Target benchmark directory (absolute path)
                        "--output-sarif", str(cthive_sarif),
                        "--no-git"  # Disable Git repository detection
                    ]
                    
                    logging.info(f"Running CodeThreat Hive command: {' '.join(cthive_cmd)}")
                    logging.info(f"Running from CodeThreat Hive root: {cthive_root_path}")
                    
                    # Change to CodeThreat Hive root directory before running
                    original_dir = os.getcwd()
                    os.chdir(str(cthive_root_path))
                    
                    try:
                        # Run CodeThreat Hive with real-time output streaming
                        logging.info("CodeThreat Hive scan starting...")
                        print(f"\n{'='*70}")
                        print(f"[CodeThreat Hive] Scanning: {Path(dir_path).name}")
                        print(f"{'='*70}\n")
                        
                        process = subprocess.Popen(
                            cthive_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,  # Combine stderr with stdout
                            text=True,
                            bufsize=0,  # Unbuffered for immediate output
                            universal_newlines=True
                        )
                        
                        # Stream output in real-time
                        output_lines = []
                        import threading
                        import time
                        
                        start_time = time.time()
                        timeout_seconds = 600  # 10 minutes
                        last_output_time = time.time()
                        
                        # Read output in a separate thread
                        def read_output():
                            nonlocal last_output_time
                            for line in iter(process.stdout.readline, ''):
                                if line:
                                    line = line.rstrip()
                                    # Print directly to stdout for real-time visibility
                                    print(f"[CodeThreat Hive] {line}", flush=True)
                                    output_lines.append(line)
                                    last_output_time = time.time()
                            process.stdout.close()
                        
                        # Start output reading thread
                        output_thread = threading.Thread(target=read_output, daemon=True)
                        output_thread.start()
                        
                        # Wait for process with timeout checking and progress indication
                        exit_code = None
                        while exit_code is None:
                            exit_code = process.poll()
                            if exit_code is None:
                                # Check timeout
                                elapsed = time.time() - start_time
                                if elapsed > timeout_seconds:
                                    logging.error(f"CodeThreat Hive scan timed out after 10 minutes for {dir_path}")
                                    process.kill()
                                    process.wait()
                                    exit_code = -1
                                    break
                                
                                # Show progress if no output for 30 seconds
                                if time.time() - last_output_time > 30 and elapsed > 30:
                                    print(f"[CodeThreat Hive] Still processing... ({int(elapsed)}s elapsed)", flush=True)
                                    last_output_time = time.time()  # Reset to avoid spam
                                
                                time.sleep(0.5)  # Check every 500ms
                        
                        # Wait for output thread to finish reading (with longer timeout)
                        output_thread.join(timeout=5)
                        
                        logging.info(f"CodeThreat Hive exit code: {exit_code}")
                        
                        # Log summary if there was output
                        if output_lines:
                            logging.info(f"CodeThreat Hive produced {len(output_lines)} lines of output")
                        print()  # Add blank line after CodeThreat Hive output
                        
                        # Check if SARIF file was created
                        if cthive_sarif.exists():
                            logging.info(f"✓ CodeThreat Hive SARIF file created: {cthive_sarif}")
                            with open(cthive_sarif, 'r') as f:
                                file_size = len(f.read())
                                logging.info(f"SARIF file size: {file_size} bytes")
                        else:
                            logging.error(f"✗ CodeThreat Hive SARIF file not created at: {cthive_sarif}")
                            if exit_code != 0:
                                logging.error(f"Exit code: {exit_code}")
                            if output_lines:
                                # Show last few lines for debugging
                                logging.error("Last output lines:")
                                for line in output_lines[-10:]:
                                    logging.error(f"  {line}")
                            
                    except Exception as e:
                        logging.error(f"Error running CodeThreat Hive: {str(e)}")
                        if 'process' in locals() and process.poll() is None:
                            process.kill()
                    finally:
                        # Return to original directory
                        os.chdir(original_dir)
        else:
            logging.info(f"Skipping CodeThreat Hive scan - SARIF file already exists: {cthive_sarif}")
        
        logging.info(f"Completed scan for directory: {dir_path}")
                
    except Exception as e:
        logging.error(f"Unexpected error for {subdir}: {str(e)}")
        raise
    finally:
        # Always restore SARIF files from backup, even if scan failed
        if temp_backup_dir:
            restore_sarif_files(dir_path, temp_backup_dir)

def scan_dirs_with_sast(base_path: str, max_number: int):
    """
    Scan directories with SAST tools sequentially
    
    Args:
        base_path: Base directory containing subdirectories to scan
        max_number: Maximum number for XBEN pattern matching
    """
    base_dir = Path(base_path).resolve()  # Get absolute path
    logging.info(f"Starting scans in base directory: {base_dir} with max number: {max_number}")
    
    if not base_dir.exists():
        logging.error(f"Base directory {base_dir} does not exist")
        return
    
    # Get all immediate subdirectories that match XBEN pattern with specified max_number
    subdirs = [
        str(d) for d in base_dir.iterdir() 
        if d.is_dir() and 
        d.name.startswith("XBEN-") and 
        d.name.endswith("-24") and
        1 <= int(d.name.split("-")[1]) <= max_number
    ]
    
    if not subdirs:
        logging.warning(f"No matching XBEN subdirectories found in {base_dir}")
        return
    
    # Sort subdirs for consistent ordering
    subdirs.sort()
    
    logging.info(f"Found {len(subdirs)} directories to scan in {base_dir}")
    logging.info(f"Directories: {', '.join([Path(d).name for d in subdirs[:5]])}{'...' if len(subdirs) > 5 else ''}")
    
    # Run scans sequentially
    for i, subdir in enumerate(subdirs, 1):
        logging.info(f"[{i}/{len(subdirs)}] Processing {Path(subdir).name}")
        try:
            run_sast_scan(subdir)
            logging.info(f"Successfully completed all scans for: {Path(subdir).name}")
        except Exception as e:
            logging.error(f"Failed to complete scans for {Path(subdir).name}: {str(e)}")
    
    logging.info(f"All SAST scans completed for {base_dir}")

def run_scans(directory1: str, directory2: str):
    """
    Run scans on two directories sequentially
    
    Args:
        directory1: First directory to scan (benchmarks)
        directory2: Second directory to scan (benchmarks_patched)
    """
    logging.info("=" * 70)
    logging.info("Starting SAST scans")
    logging.info("=" * 70)
    
    # Scan benchmarks directory
    logging.info(f"\nScanning {directory1} (vulnerable benchmarks)")
    logging.info("-" * 70)
    scan_dirs_with_sast(directory1, 51)
    
    # Scan benchmarks_patched directory
    logging.info(f"\nScanning {directory2} (patched benchmarks)")
    logging.info("-" * 70)
    scan_dirs_with_sast(directory2, 25)
    
    logging.info("=" * 70)
    logging.info("All directory scans completed")
    logging.info("=" * 70)

if __name__ == "__main__":
    directory1 = "benchmarks/"
    directory2 = "benchmarks_patched/"
    
    print("=" * 70)
    print("Starting SAST Scan Pipeline")
    print("=" * 70)
    print(f"Scanning directories:")
    print(f"  - {directory1} (max 51 benchmarks)")
    print(f"  - {directory2} (max 25 benchmarks)")
    print("=" * 70)
    print()
    
    run_scans(directory1, directory2)
    
    print()
    print("=" * 70)
    print("SAST Scan Pipeline Completed")
    print("=" * 70)