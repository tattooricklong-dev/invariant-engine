"""
Iron Supervisor v2 — Alienware Hardware Boundary Governor & Telemetry Ledger
Target OS: Windows 11 (Alienware Aurora R16)
Architecture: Standard Library Only / Zero Third-Party Dependencies (ctypes + win32)
Triad Contract: Architect (Invariants), Shadowsmith (Noise Filter), Arbiter (Resource Limits)
"""

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
import json
import logging
import os
from pathlib import Path
import queue
import signal
import sys
import threading
import time
from typing import Any, Dict, Optional

# ==============================================================================
# NATIVE WIN32 KERNEL STRUCTURES & CALLS
# ==============================================================================

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# Resilient Win32 entry-point resolution
if hasattr(psapi, "GetProcessMemoryCounters"):
    _get_proc_mem = psapi.GetProcessMemoryCounters
elif hasattr(kernel32, "K32GetProcessMemoryCounters"):
    _get_proc_mem = kernel32.K32GetProcessMemoryCounters
else:
    _get_proc_mem = None

# ==============================================================================
# TELEMETRY RECORD & HARDWARE PROBE ENGINE
# ==============================================================================

@dataclass(frozen=True)
class HardwareSnapshot:
    timestamp_ns: int
    memory_load_percent: int
    phys_total_mb: float
    phys_avail_mb: float
    pagefile_total_mb: float
    pagefile_avail_mb: float
    process_working_set_mb: float
    process_pagefile_mb: float
    io_read_bytes: int
    io_write_bytes: int
    status_flag: str  # NOMINAL, THROTTLE, CRITICAL

def query_system_hardware() -> HardwareSnapshot:
    """Probes physical RAM, Pagefile, and Process I/O directly from Win32 kernel."""
    mem_status = MEMORYSTATUSEX()
    mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))

    proc_handle = kernel32.GetCurrentProcess()
    proc_counters = PROCESS_MEMORY_COUNTERS()
    proc_counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    
    if _get_proc_mem:
        _get_proc_mem(proc_handle, ctypes.byref(proc_counters), proc_counters.cb)

    io_counters = IO_COUNTERS()
    kernel32.GetProcessIoCounters(proc_handle, ctypes.byref(io_counters))

    mem_load = mem_status.dwMemoryLoad
    status = "NOMINAL"
    if mem_load >= 85:
        status = "CRITICAL"
    elif mem_load >= 75:
        status = "THROTTLE"

    return HardwareSnapshot(
        timestamp_ns=time.perf_counter_ns(),
        memory_load_percent=mem_load,
        phys_total_mb=round(mem_status.ullTotalPhys / (1024 * 1024), 2),
        phys_avail_mb=round(mem_status.ullAvailPhys / (1024 * 1024), 2),
        pagefile_total_mb=round(mem_status.ullTotalPageFile / (1024 * 1024), 2),
        pagefile_avail_mb=round(mem_status.ullAvailPageFile / (1024 * 1024), 2),
        process_working_set_mb=round(proc_counters.WorkingSetSize / (1024 * 1024), 2),
        process_pagefile_mb=round(proc_counters.PagefileUsage / (1024 * 1024), 2),
        io_read_bytes=io_counters.ReadTransferCount,
        io_write_bytes=io_counters.WriteTransferCount,
        status_flag=status,
    )

# ==============================================================================
# ATOMIC PERSISTENCE & TELEMETRY LEDGER (ARBITER GATE)
# ==============================================================================

class TelemetryLedgerSink:
    """Non-blocking, ring-bounded ledger sink with atomic filesystem flush."""

    def __init__(self, ledger_dir: Path, max_queue_size: int = 10000):
        self.ledger_dir = ledger_dir
        self.ledger_file = ledger_dir / "live_telemetry_ledger.json"
        self.pulse_file = ledger_dir / "pulse.txt"
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self.drain_thread = threading.Thread(target=self._drain_loop, daemon=True, name="SinkDrainingThread")
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.drain_thread.start()

    def submit(self, snapshot: HardwareSnapshot):
        try:
            self.queue.put_nowait(snapshot)
        except queue.Full:
            try:
                _ = self.queue.get_nowait()
                self.queue.put_nowait(snapshot)
            except Exception:
                pass

    def _drain_loop(self):
        buffer = []
        last_flush = time.monotonic()

        while self.running or not self.queue.empty():
            try:
                item = self.queue.get(timeout=0.25)
                buffer.append(asdict(item))
            except queue.Empty:
                pass

            now = time.monotonic()
            if buffer and (len(buffer) >= 20 or (now - last_flush) >= 2.0):
                self._flush_atomic(buffer)
                buffer.clear()
                last_flush = now

    def _flush_atomic(self, records: list):
        temp_file = self.ledger_dir / f"ledger_tmp_{os.getpid()}.json"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, self.ledger_file)

            with open(self.pulse_file, "w", encoding="utf-8") as pf:
                pf.write(f"HEARTBEAT: {time.time()} | RECORDS: {len(records)}\n")
        except Exception as e:
            sys.stderr.write(f"[SINK_ERROR] Atomic ledger flush failed: {e}\n")
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    def close(self):
        self.running = False
        if self.drain_thread.is_alive():
            self.drain_thread.join(timeout=3.0)

# ==============================================================================
# SUPERVISOR V2 RUNTIME GOVERNOR (THE HARNESS)
# ==============================================================================

class IronSupervisorV2:
    def __init__(self, root_dir: str = "B:\\PromptEngine", target_cadence_s: float = 1.0):
        self.root_dir = Path(root_dir)
        self.cadence_ns = int(target_cadence_s * 1_000_000_000)
        self.sink = TelemetryLedgerSink(self.root_dir / "telemetry")
        self.active = True
        self.last_load_percent = -1

        signal.signal(signal.SIGINT, self._handle_teardown)
        signal.signal(signal.SIGTERM, self._handle_teardown)

    def _handle_teardown(self, signum, frame):
        sys.stdout.write(f"\n[SUPERVISOR] Termination signal ({signum}) intercepted. Draining pipeline...\n")
        self.active = False

    def run(self):
        sys.stdout.write("================================================================\n")
        sys.stdout.write("  IRON SUPERVISOR V2 ACTIVE // ALIENWARE TELEMETRY AUDIT HARNESS\n")
        sys.stdout.write(f"  Target Root: {self.root_dir}\n")
        sys.stdout.write("================================================================\n")

        next_tick = time.perf_counter_ns()

        while self.active:
            snapshot = query_system_hardware()

            if abs(snapshot.memory_load_percent - self.last_load_percent) >= 3 or snapshot.status_flag != "NOMINAL":
                sys.stdout.write(
                    f"[{snapshot.status_flag}] RAM Load: {snapshot.memory_load_percent}% | "
                    f"Phys Avail: {snapshot.phys_avail_mb:.0f} MB | "
                    f"Process WS: {snapshot.process_working_set_mb:.1f} MB | "
                    f"Pagefile: {snapshot.pagefile_avail_mb:.0f} MB free\n"
                )
                self.last_load_percent = snapshot.memory_load_percent

            self.sink.submit(snapshot)

            next_tick += self.cadence_ns
            drift = next_tick - time.perf_counter_ns()

            if drift > 0:
                time.sleep(drift / 1_000_000_000.0)
            else:
                next_tick = time.perf_counter_ns()

        self.sink.close()
        sys.stdout.write("[SUPERVISOR] Ledger flushed cleanly. Process halted with exit code 130.\n")
        sys.exit(130)

if __name__ == "__main__":
    governor = IronSupervisorV2()
    governor.run()