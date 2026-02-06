#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
확장된 공장초기화 아티팩트 분석기 (통합 버전)
Extended Factory Reset Artifact Analyzer - All-in-One

GUI와 분석 엔진이 하나의 파일에 통합됨
"""

import sys
import os
import re
import zipfile
import sqlite3
import subprocess
import json
import struct
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import xml.etree.ElementTree as ET
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QPushButton,
    QCheckBox, QLabel, QLineEdit, QFileDialog, QProgressBar, QMessageBox,
    QGroupBox, QGridLayout, QSplitter, QHeaderView, QFrame,
    QButtonGroup, QRadioButton
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont


# ============================================================================
# 분석 엔진 클래스
# ============================================================================

class ExtendedFactoryResetAnalyzer:
    """확장된 공장초기화 아티팩트 분석기"""
    
    def __init__(self, source_path: str, source_type: str = "zip"):
        self.source_path = source_path
        self.source_type = source_type
        self.discovered_artifacts = {}
        self.timestamp_patterns = self._initialize_patterns()
        self.extended_paths = self._initialize_extended_paths()
        self.correlation_results = {}
        
    def _initialize_patterns(self) -> Dict[str, str]:
        """확장된 타임스탬프 패턴 초기화"""
        return {
            "iso_datetime": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
            "standard_datetime": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            "epoch_10": r"\b1[5-7]\d{8}\b",
            "epoch_13": r"\b1[5-7]\d{11}\b",
            "android_log_time": r"\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}",
            "recovery_log_time": r"[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}",
            "bootstat_time": r"boot_complete_\d+",
            "xml_timestamp": r'(?:time|Time|timestamp|Timestamp)="(\d+)"',
            "xml_epoch": r'value="(\d{10,13})"',
            "xml_datetime": r'(?:date|Date|datetime|DateTime)="([^"]+)"',
            "factory_reset": r"factory.*reset|reset.*factory|wipe.*data|format.*userdata",
            "setup_wizard": r"setup.*wizard|wizard.*setup|first.*boot|initial.*setup",
            "oobe": r"out.*of.*box|oobe|welcome.*screen|setup.*complete"
        }
    
    def _initialize_extended_paths(self) -> List[str]:
        """확장된 검색 경로 초기화"""
        return [
            "Dump/data/misc/bootstat/", "Dump/cache/recovery/", "Dump/data/log/",
            "Dump/data/system/", "Dump/data/property/", "Dump/data/anr/",
            "Dump/data/tombstones/", "Dump/data/system/dropbox/", "Dump/data/misc/logd/",
            "Dump/data/system/usagestats/", "Dump/data/data/com.android.providers.settings/",
            "Dump/data/data/com.google.android.setupwizard/", "Dump/data/data/com.android.managedprovisioning/",
            "Dump/system/recovery-resource.dat", "Dump/proc/", "Dump/data/system/users/",
            "Dump/data/misc/user/", "Dump/data/misc/wifi/", "Dump/data/misc/bluetooth/",
            "Dump/data/misc/systemkeys/", "Dump/data/data/*/databases/",
            "Dump/data/data/*/shared_prefs/", "Dump/data/data/*/files/",
        ]
    
    def analyze_file_metadata(self) -> Dict[str, Any]:
        """파일 시스템 메타데이터 분석"""
        metadata_results = {"suspicious_files": [], "timeline_files": [], "creation_clusters": {}, "modification_patterns": {}}
        if self.source_type == "zip":
            metadata_results.update(self._analyze_zip_metadata())
        elif self.source_type == "folder":
            metadata_results.update(self._analyze_folder_metadata())
        elif self.source_type == "adb":
            metadata_results.update(self._analyze_adb_metadata())
        return metadata_results
    
    def _analyze_zip_metadata(self) -> Dict[str, Any]:
        """ZIP 파일의 메타데이터 분석"""
        results = {"zip_files": []}
        try:
            with zipfile.ZipFile(self.source_path, 'r') as zip_ref:
                for info in zip_ref.infolist():
                    if not info.is_dir():
                        file_time = datetime(*info.date_time)
                        file_info = {"path": info.filename, "size": info.file_size, "compressed_size": info.compress_size,
                                    "modification_time": file_time, "crc": hex(info.CRC)}
                        if self._is_factory_reset_related(info.filename):
                            file_info["factory_reset_related"] = True
                            results["zip_files"].append(file_info)
        except Exception as e:
            pass
        return results
    
    def _analyze_folder_metadata(self) -> Dict[str, Any]:
        """폴더의 메타데이터 분석"""
        results = {"folder_files": []}
        try:
            for root, dirs, files in os.walk(self.source_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        stat = os.stat(file_path)
                        file_info = {"path": file_path, "size": stat.st_size,
                                    "modification_time": datetime.fromtimestamp(stat.st_mtime),
                                    "creation_time": datetime.fromtimestamp(stat.st_ctime),
                                    "access_time": datetime.fromtimestamp(stat.st_atime)}
                        if self._is_factory_reset_related(file_path):
                            file_info["factory_reset_related"] = True
                            results["folder_files"].append(file_info)
        except Exception:
            pass
        return results
    
    def _analyze_adb_metadata(self) -> Dict[str, Any]:
        """ADB를 통한 메타데이터 분석"""
        results = {"adb_files": []}
        try:
            for path in self.extended_paths:
                clean_path = path.replace("Dump/", "/")
                cmd = ["adb", "shell", "find", clean_path, "-type", "f", "-ls", "2>/dev/null"]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        files = self._parse_adb_file_list(result.stdout)
                        results["adb_files"].extend(files)
                except:
                    pass
        except Exception:
            pass
        return results
    
    def analyze_extended_logs(self) -> Dict[str, Any]:
        """확장된 로그 파일 분석"""
        return {
            "anr_logs": self._analyze_anr_logs(),
            "tombstone_logs": self._analyze_tombstone_logs(),
            "dropbox_logs": self._analyze_dropbox_logs(),
            "kernel_logs": self._analyze_kernel_logs(),
            "logcat_archives": self._analyze_logcat_archives()
        }
    
    def _analyze_anr_logs(self) -> List[Dict[str, Any]]:
        """ANR 로그 분석"""
        anr_files = []
        files = self._get_files_in_path("Dump/data/anr/")
        for file_path in files:
            try:
                content = self._read_file_content(file_path)
                if content:
                    timestamps = self._extract_timestamps_from_text(content)
                    if timestamps:
                        anr_files.append({"file": file_path, "timestamps": timestamps, "content_preview": content[:200]})
            except Exception:
                pass
        return anr_files
    
    def _analyze_tombstone_logs(self) -> List[Dict[str, Any]]:
        """Tombstone 로그 분석"""
        tombstone_files = []
        files = self._get_files_in_path("Dump/data/tombstones/")
        for file_path in files:
            try:
                content = self._read_file_content(file_path)
                if content:
                    crash_time = self._extract_crash_timestamp(content)
                    if crash_time:
                        tombstone_files.append({"file": file_path, "crash_time": crash_time, "content_preview": content[:200]})
            except Exception:
                pass
        return tombstone_files
    
    def _analyze_dropbox_logs(self) -> List[Dict[str, Any]]:
        """Dropbox 로그 분석"""
        dropbox_files = []
        files = self._get_files_in_path("Dump/data/system/dropbox/")
        for file_path in files:
            try:
                timestamp = self._extract_timestamp_from_filename(file_path)
                if timestamp:
                    content = self._read_file_content(file_path)
                    dropbox_files.append({"file": file_path, "timestamp": timestamp, "content_preview": content[:200] if content else ""})
            except Exception:
                pass
        return dropbox_files
    
    def _analyze_kernel_logs(self) -> List[Dict[str, Any]]:
        """Kernel 로그 분석"""
        kernel_logs = []
        for path in ["Dump/proc/kmsg", "Dump/data/dmesg", "Dump/cache/recovery/last_kmsg"]:
            try:
                if self._file_exists(path):
                    content = self._read_file_content(path)
                    if content:
                        for line_no, line in enumerate(content.split('\n')):
                            if re.search(r'factory.*reset|reset.*factory|wipe.*data', line, re.IGNORECASE):
                                kernel_logs.append({"file": path, "line_number": line_no, "content": line.strip(),
                                                   "timestamp": self._extract_kernel_timestamp(line)})
            except Exception:
                pass
        return kernel_logs
    
    def _analyze_logcat_archives(self) -> List[Dict[str, Any]]:
        """Logcat 아카이브 분석"""
        logcat_archives = []
        for base_path in ["Dump/data/misc/logd/", "Dump/cache/", "Dump/data/log/"]:
            files = self._get_files_in_path(base_path)
            for file_path in files:
                if any(keyword in file_path.lower() for keyword in ['logcat', 'main', 'system', 'events']):
                    try:
                        content = self._read_file_content(file_path)
                        if content:
                            setup_logs = []
                            for line in content.split('\n'):
                                if re.search(r'setupwizard|factory.*reset|first.*boot|oobe', line, re.IGNORECASE):
                                    timestamp = self._extract_logcat_timestamp(line)
                                    setup_logs.append({"timestamp": timestamp, "content": line.strip()})
                            if setup_logs:
                                logcat_archives.append({"file": file_path, "setup_logs": setup_logs})
                    except Exception:
                        pass
        return logcat_archives
    
    def analyze_databases(self) -> Dict[str, Any]:
        """데이터베이스 심층 분석"""
        return {
            "settings_db": self._analyze_settings_database(),
            "usage_stats": self._analyze_usage_stats(),
            "accounts_db": self._analyze_accounts_database(),
            "package_db": self._analyze_package_database()
        }
    
    def _analyze_settings_database(self) -> Dict[str, Any]:
        """Settings 데이터베이스 분석"""
        settings_path = "Dump/data/data/com.android.providers.settings/databases/settings.db"
        try:
            if self._file_exists(settings_path):
                db_content = self._read_file_bytes(settings_path)
                if db_content:
                    return self._analyze_sqlite_database(db_content, [
                        "SELECT * FROM secure WHERE name LIKE '%setup%' OR name LIKE '%reset%'",
                        "SELECT * FROM global WHERE name LIKE '%boot%' OR name LIKE '%first%'",
                        "SELECT * FROM system WHERE name LIKE '%wizard%'"
                    ])
        except Exception:
            pass
        return {"error": "Settings 데이터베이스를 분석할 수 없습니다"}
    
    def _analyze_usage_stats(self) -> List[Dict[str, Any]]:
        """사용 통계 분석"""
        usage_stats = []
        files = self._get_files_in_path("Dump/data/system/usagestats/")
        for file_path in files:
            try:
                if file_path.endswith('.xml'):
                    content = self._read_file_content(file_path)
                    if content:
                        stats = self._parse_usage_stats_xml(content)
                        if stats:
                            usage_stats.append({"file": file_path, "stats": stats})
            except Exception:
                pass
        return usage_stats
    
    def _analyze_accounts_database(self) -> Dict[str, Any]:
        """Accounts 데이터베이스 분석"""
        return {"info": "Accounts DB 분석 기능"}
    
    def _analyze_package_database(self) -> Dict[str, Any]:
        """Package 데이터베이스 분석"""
        return {"info": "Package DB 분석 기능"}
    
    def perform_extended_pattern_search(self) -> Dict[str, Any]:
        """확장된 패턴 기반 검색"""
        pattern_results = {}
        for pattern_name, pattern in self.timestamp_patterns.items():
            matches = self._search_pattern_in_all_files(pattern)
            if matches:
                pattern_results[pattern_name] = matches
        return pattern_results
    
    def _search_pattern_in_all_files(self, pattern: str) -> List[Dict[str, Any]]:
        """모든 파일에서 패턴 검색"""
        matches = []
        try:
            all_files = self._get_all_searchable_files()
            for file_path in all_files:
                try:
                    content = self._read_file_content(file_path)
                    if content:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            matches.append({"file": file_path, "match": match.group(), "position": match.span(),
                                         "context": content[max(0, match.start()-50):match.end()+50]})
                except Exception:
                    continue
        except Exception:
            pass
        return matches
    
    def analyze_binary_artifacts(self) -> Dict[str, Any]:
        """바이너리 아티팩트 분석"""
        return {"hex_timestamps": self._search_hex_timestamps(), "binary_strings": [], "file_signatures": []}
    
    def _search_hex_timestamps(self) -> List[Dict[str, Any]]:
        """바이너리 파일에서 HEX 타임스탬프 검색"""
        hex_timestamps = []
        binary_files = self._get_binary_files()
        for file_path in binary_files:
            try:
                raw_data = self._read_file_bytes(file_path)
                if raw_data:
                    for i in range(0, len(raw_data) - 4, 4):
                        timestamp = struct.unpack('<I', raw_data[i:i+4])[0]
                        if 1500000000 < timestamp < 1800000000:
                            hex_timestamps.append({"file": file_path, "offset": i, "timestamp": timestamp,
                                                  "datetime": datetime.fromtimestamp(timestamp),
                                                  "hex_value": raw_data[i:i+4].hex()})
            except Exception:
                pass
        return hex_timestamps
    
    def perform_correlation_analysis(self) -> Dict[str, Any]:
        """상관관계 분석"""
        all_timestamps = self._collect_all_timestamps()
        return {
            "timeline": self._create_chronological_timeline(all_timestamps),
            "clusters": self._find_timestamp_clusters(all_timestamps),
            "outliers": self._detect_timestamp_outliers(all_timestamps),
            "consistency": self._check_timestamp_consistency(all_timestamps),
            "missing_gaps": self._identify_missing_timestamps(all_timestamps)
        }
    
    def _collect_all_timestamps(self) -> List[Dict[str, Any]]:
        """발견된 모든 타임스탬프 수집"""
        return []
    
    def reconstruct_timeline(self) -> Dict[str, Any]:
        """타임라인 재구성"""
        timeline = {"pre_reset": [], "reset_process": [], "post_reset": [], "reconstruction_confidence": 0.0}
        all_timestamps = self._collect_all_timestamps()
        if all_timestamps:
            sorted_timestamps = sorted(all_timestamps, key=lambda x: x.get('datetime', datetime.min))
            reset_time = self._estimate_factory_reset_time(sorted_timestamps)
            if reset_time:
                for ts in sorted_timestamps:
                    ts_time = ts.get('datetime')
                    if ts_time:
                        if ts_time < reset_time - timedelta(hours=1):
                            timeline["pre_reset"].append(ts)
                        elif reset_time - timedelta(hours=1) <= ts_time <= reset_time + timedelta(hours=1):
                            timeline["reset_process"].append(ts)
                        else:
                            timeline["post_reset"].append(ts)
                timeline["reconstruction_confidence"] = self._calculate_timeline_confidence(timeline)
        return timeline
    
    def generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """분석 요약 생성"""
        summary = {"total_artifacts_found": len(self.discovered_artifacts), "new_timestamp_sources": 0,
                  "confidence_level": "medium", "recommendations": [], "key_findings": []}
        for analysis_type, data in results.items():
            if analysis_type != "summary" and data:
                if isinstance(data, dict):
                    for key, value in data.items():
                        if value and len(value) > 0:
                            summary["new_timestamp_sources"] += 1
                            summary["key_findings"].append(f"{analysis_type}.{key}에서 {len(value)}개 발견")
        if summary["new_timestamp_sources"] > 10:
            summary["confidence_level"] = "high"
            summary["recommendations"].append("높은 신뢰도의 타임라인 재구성 가능")
        elif summary["new_timestamp_sources"] > 5:
            summary["confidence_level"] = "medium"
            summary["recommendations"].append("중간 신뢰도의 분석 결과")
        else:
            summary["confidence_level"] = "low"
            summary["recommendations"].append("추가 분석이 필요함")
        return summary
    
    def _is_factory_reset_related(self, file_path: str) -> bool:
        """파일이 공장초기화와 관련된지 확인"""
        keywords = ["factory", "reset", "wipe", "setup", "boot", "recovery", "first", "initial"]
        return any(keyword in file_path.lower() for keyword in keywords)
    
    def _get_files_in_path(self, path: str) -> List[str]:
        """경로에서 파일 목록 가져오기"""
        files = []
        try:
            if self.source_type == "zip":
                with zipfile.ZipFile(self.source_path, 'r') as zip_ref:
                    for name in zip_ref.namelist():
                        if name.startswith(path) and not name.endswith('/'):
                            files.append(name)
            elif self.source_type == "folder":
                actual_path = os.path.join(self.source_path, path.replace("Dump/", ""))
                if os.path.exists(actual_path):
                    for root, dirs, filenames in os.walk(actual_path):
                        for filename in filenames:
                            files.append(os.path.join(root, filename))
            elif self.source_type == "adb":
                clean_path = path.replace("Dump/", "/")
                cmd = ["adb", "shell", "find", clean_path, "-type", "f", "2>/dev/null"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    files = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        except Exception:
            pass
        return files
    
    def _read_file_content(self, file_path: str) -> Optional[str]:
        """파일 내용을 텍스트로 읽기"""
        try:
            if self.source_type == "zip":
                with zipfile.ZipFile(self.source_path, 'r') as zip_ref:
                    with zip_ref.open(file_path) as file:
                        return file.read().decode('utf-8', errors='ignore')
            elif self.source_type == "folder":
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    return file.read()
            elif self.source_type == "adb":
                cmd = ["adb", "shell", "cat", file_path, "2>/dev/null"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return result.stdout
        except Exception:
            pass
        return None
    
    def _read_file_bytes(self, file_path: str) -> Optional[bytes]:
        """파일 내용을 바이트로 읽기"""
        try:
            if self.source_type == "zip":
                with zipfile.ZipFile(self.source_path, 'r') as zip_ref:
                    with zip_ref.open(file_path) as file:
                        return file.read()
            elif self.source_type == "folder":
                with open(file_path, 'rb') as file:
                    return file.read()
        except Exception:
            pass
        return None
    
    def _file_exists(self, file_path: str) -> bool:
        """파일 존재 여부 확인"""
        try:
            if self.source_type == "zip":
                with zipfile.ZipFile(self.source_path, 'r') as zip_ref:
                    return file_path in zip_ref.namelist()
            elif self.source_type == "folder":
                return os.path.exists(file_path)
            elif self.source_type == "adb":
                cmd = ["adb", "shell", "test", "-f", file_path]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                return result.returncode == 0
        except Exception:
            pass
        return False
    
    def _extract_timestamps_from_text(self, text: str) -> List[Dict[str, Any]]:
        """텍스트에서 타임스탬프 추출"""
        timestamps = []
        for pattern_name, pattern in self.timestamp_patterns.items():
            for match in re.finditer(pattern, text):
                timestamps.append({"type": pattern_name, "value": match.group(), "position": match.span()})
        return timestamps
    
    def _parse_adb_file_list(self, output: str) -> List[Dict[str, Any]]:
        """ADB 파일 목록 파싱"""
        files = []
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 8:
                        files.append({"path": ' '.join(parts[8:]), "size": parts[4], "date": parts[5],
                                    "time": parts[6], "permissions": parts[0]})
        except Exception:
            pass
        return files
    
    def _extract_kernel_timestamp(self, line: str) -> Optional[str]:
        """Kernel 로그 라인에서 타임스탬프 추출"""
        for pattern in [r'\[\s*(\d+\.\d+)\]', r'(\d{2}:\d{2}:\d{2}\.\d+)']:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def _extract_logcat_timestamp(self, line: str) -> Optional[str]:
        """Logcat 라인에서 타임스탬프 추출"""
        for pattern in [r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})']:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def _extract_timestamp_from_filename(self, filename: str) -> Optional[datetime]:
        """파일명에서 타임스탬프 추출"""
        try:
            patterns = [
                (r'(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})', '%Y%m%d_%H%M%S'),
                (r'(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})', '%Y-%m-%d_%H-%M-%S'),
                (r'(\d{13})', 'epoch_ms'), (r'(\d{10})', 'epoch_s'),
            ]
            for pattern, format_str in patterns:
                match = re.search(pattern, filename)
                if match:
                    if format_str == 'epoch_ms':
                        return datetime.fromtimestamp(int(match.group(1)) / 1000)
                    elif format_str == 'epoch_s':
                        return datetime.fromtimestamp(int(match.group(1)))
                    else:
                        time_str = '_'.join(match.groups()) if len(match.groups()) > 1 else match.group(1)
                        return datetime.strptime(time_str, format_str)
        except Exception:
            pass
        return None
    
    def _extract_crash_timestamp(self, content: str) -> Optional[datetime]:
        """Tombstone에서 크래시 시간 추출"""
        try:
            for pattern in [r'timestamp: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
                          r'Build fingerprint: .*\n.*\nTimestamp: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
                          r'ABI: .*\nTimestamp: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})']:
                match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                if match:
                    return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
        return None
    
    def _analyze_sqlite_database(self, db_content: bytes, queries: List[str]) -> Dict[str, Any]:
        """SQLite 데이터베이스 분석"""
        results = {"queries": {}, "error": None}
        try:
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
                tmp_file.write(db_content)
                tmp_path = tmp_file.name
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()
            for i, query in enumerate(queries):
                try:
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    results["queries"][f"query_{i+1}"] = {"sql": query, "columns": columns, "rows": rows[:100]}
                except Exception as e:
                    results["queries"][f"query_{i+1}"] = {"sql": query, "error": str(e)}
            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            results["error"] = f"데이터베이스 분석 오류: {e}"
        return results
    
    def _parse_usage_stats_xml(self, content: str) -> Dict[str, Any]:
        """사용 통계 XML 파싱"""
        stats = {"packages": [], "events": []}
        try:
            root = ET.fromstring(content)
            for package in root.findall('.//package'):
                package_name = package.get('name', '')
                last_time = package.get('lastTimeUsed', '')
                if package_name and last_time:
                    stats["packages"].append({"name": package_name, "last_used": last_time,
                                            "total_time": package.get('totalTimeInForeground', '0')})
            for event in root.findall('.//event'):
                timestamp = event.get('time', '')
                if timestamp:
                    stats["events"].append({"type": event.get('type', ''), "timestamp": timestamp,
                                           "package": event.get('package', '')})
        except Exception:
            pass
        return stats
    
    def _get_all_searchable_files(self) -> List[str]:
        """검색 가능한 모든 파일 목록 반환"""
        all_files = []
        for path in self.extended_paths:
            files = self._get_files_in_path(path)
            all_files.extend(files)
        return all_files
    
    def _get_binary_files(self) -> List[str]:
        """바이너리 분석 대상 파일들 반환"""
        binary_extensions = ['.db', '.dat', '.bin', '.so', '.apk']
        binary_files = []
        all_files = self._get_all_searchable_files()
        for file_path in all_files:
            if any(file_path.lower().endswith(ext) for ext in binary_extensions):
                binary_files.append(file_path)
        return binary_files
    
    def _create_chronological_timeline(self, timestamps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """시간순 타임라인 생성"""
        try:
            valid_timestamps = [ts for ts in timestamps if isinstance(ts.get('datetime'), datetime)]
            return sorted(valid_timestamps, key=lambda x: x['datetime'])
        except Exception:
            return []
    
    def _find_timestamp_clusters(self, timestamps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """타임스탬프 클러스터 찾기"""
        clusters = []
        try:
            if not timestamps:
                return clusters
            timeline = self._create_chronological_timeline(timestamps)
            if not timeline:
                return clusters
            current_cluster = [timeline[0]]
            cluster_threshold = timedelta(hours=1)
            for i in range(1, len(timeline)):
                prev_time = timeline[i-1]['datetime']
                curr_time = timeline[i]['datetime']
                if curr_time - prev_time <= cluster_threshold:
                    current_cluster.append(timeline[i])
                else:
                    if len(current_cluster) >= 2:
                        clusters.append({"start_time": current_cluster[0]['datetime'],
                                       "end_time": current_cluster[-1]['datetime'],
                                       "count": len(current_cluster), "timestamps": current_cluster})
                    current_cluster = [timeline[i]]
            if len(current_cluster) >= 2:
                clusters.append({"start_time": current_cluster[0]['datetime'],
                               "end_time": current_cluster[-1]['datetime'],
                               "count": len(current_cluster), "timestamps": current_cluster})
        except Exception:
            pass
        return clusters
    
    def _detect_timestamp_outliers(self, timestamps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """타임스탬프 이상치 탐지"""
        outliers = []
        try:
            timeline = self._create_chronological_timeline(timestamps)
            if len(timeline) < 3:
                return outliers
            intervals = [(timeline[i]['datetime'] - timeline[i-1]['datetime']).total_seconds()
                        for i in range(1, len(timeline))]
            if not intervals:
                return outliers
            intervals.sort()
            q1 = intervals[len(intervals)//4]
            q3 = intervals[3*len(intervals)//4]
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            for i in range(1, len(timeline)):
                interval = (timeline[i]['datetime'] - timeline[i-1]['datetime']).total_seconds()
                if interval < lower_bound or interval > upper_bound:
                    outliers.append({"timestamp": timeline[i], "interval": interval, "reason": "statistical_outlier"})
        except Exception:
            pass
        return outliers
    
    def _check_timestamp_consistency(self, timestamps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """타임스탬프 일관성 검사"""
        consistency = {"total_count": len(timestamps), "valid_count": 0, "timezone_issues": [],
                      "format_issues": [], "logical_issues": []}
        try:
            for ts in timestamps:
                dt = ts.get('datetime')
                if isinstance(dt, datetime):
                    consistency["valid_count"] += 1
                    if dt.year < 2017 or dt.year > 2030:
                        consistency["logical_issues"].append({"timestamp": ts, "issue": "unrealistic_year"})
                    if dt > datetime.now() + timedelta(days=1):
                        consistency["logical_issues"].append({"timestamp": ts, "issue": "future_timestamp"})
        except Exception:
            pass
        return consistency
    
    def _identify_missing_timestamps(self, timestamps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """누락된 타임스탬프 식별"""
        missing_periods = []
        try:
            timeline = self._create_chronological_timeline(timestamps)
            if len(timeline) < 2:
                return missing_periods
            gap_threshold = timedelta(hours=1)
            for i in range(1, len(timeline)):
                time_gap = timeline[i]['datetime'] - timeline[i-1]['datetime']
                if time_gap > gap_threshold:
                    missing_periods.append({"start": timeline[i-1]['datetime'],
                                          "end": timeline[i]['datetime'],
                                          "duration_hours": time_gap.total_seconds() / 3600,
                                          "potential_missing_events": self._suggest_missing_events(time_gap)})
        except Exception:
            pass
        return missing_periods
    
    def _suggest_missing_events(self, gap: timedelta) -> List[str]:
        """시간 간격에 따른 누락 가능한 이벤트 제안"""
        hours = gap.total_seconds() / 3600
        if hours > 24:
            return ["시스템 종료 기간"]
        elif hours > 8:
            return ["장기간 유휴 상태"]
        elif hours > 2:
            return ["사용자 비활성 기간"]
        else:
            return ["일시적 로그 중단"]
    
    def _estimate_factory_reset_time(self, timestamps: List[Dict[str, Any]]) -> Optional[datetime]:
        """공장초기화 시점 추정"""
        try:
            reset_candidates = []
            for ts in timestamps:
                source = ts.get('source', '').lower()
                description = ts.get('description', '').lower()
                if any(keyword in source + description for keyword in ['factory', 'reset', 'setup', 'boot', 'recovery']):
                    reset_candidates.append(ts)
            if reset_candidates:
                earliest = min(reset_candidates, key=lambda x: x.get('datetime', datetime.max))
                return earliest.get('datetime')
        except Exception:
            pass
        return None
    
    def _calculate_timeline_confidence(self, timeline: Dict[str, Any]) -> float:
        """타임라인 재구성 신뢰도 계산"""
        try:
            total_events = (len(timeline.get('pre_reset', [])) + len(timeline.get('reset_process', [])) +
                          len(timeline.get('post_reset', [])))
            if total_events == 0:
                return 0.0
            base_confidence = min(0.5, total_events * 0.1)
            if timeline.get('reset_process'):
                base_confidence += 0.3
            if timeline.get('pre_reset') and timeline.get('post_reset'):
                base_confidence += 0.2
            return min(1.0, base_confidence)
        except Exception:
            return 0.0


# ============================================================================
# GUI 클래스
# ============================================================================

class ExtendedAnalysisWorkerThread(QThread):
    """확장 분석을 백그라운드에서 실행하는 워커 쓰레드"""
    
    analysis_started = pyqtSignal(str)
    progress_updated = pyqtSignal(str, int)
    category_completed = pyqtSignal(str, dict)
    analysis_completed = pyqtSignal(dict)
    analysis_failed = pyqtSignal(str)
    log_message = pyqtSignal(str)
    
    def __init__(self, source_path: str, source_type: str, selected_analyses: list):
        super().__init__()
        self.source_path = source_path
        self.source_type = source_type
        self.selected_analyses = selected_analyses
        self.is_cancelled = False
        
    def run(self):
        """분석 실행"""
        try:
            self.analysis_started.emit("확장 분석을 시작합니다...")
            self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] 분석 시작")
            
            analyzer = ExtendedFactoryResetAnalyzer(self.source_path, self.source_type)
            total_analyses = len(self.selected_analyses)
            completed_analyses = 0
            results = {}
            
            analysis_methods = {
                "metadata": ("파일 메타데이터 분석", analyzer.analyze_file_metadata),
                "extended_logs": ("확장 로그 분석", analyzer.analyze_extended_logs),
                "databases": ("데이터베이스 분석", analyzer.analyze_databases),
                "patterns": ("패턴 기반 검색", analyzer.perform_extended_pattern_search),
                "binary": ("바이너리 분석", analyzer.analyze_binary_artifacts),
                "correlation": ("상관관계 분석", analyzer.perform_correlation_analysis),
                "timeline": ("타임라인 재구성", analyzer.reconstruct_timeline)
            }
            
            for analysis_key in self.selected_analyses:
                if self.is_cancelled:
                    break
                if analysis_key in analysis_methods:
                    analysis_name, analysis_method = analysis_methods[analysis_key]
                    self.progress_updated.emit(f"{analysis_name} 진행 중...",
                                             int((completed_analyses / total_analyses) * 100))
                    self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] {analysis_name} 시작")
                    try:
                        result = analysis_method()
                        results[analysis_key] = result
                        self.category_completed.emit(analysis_key, result)
                        self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] {analysis_name} 완료")
                    except Exception as e:
                        error_msg = f"{analysis_name} 실패: {str(e)}"
                        self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] {error_msg}")
                        results[analysis_key] = {"error": error_msg}
                completed_analyses += 1
            
            if not self.is_cancelled:
                results["summary"] = analyzer.generate_analysis_summary(results)
                self.progress_updated.emit("분석 완료!", 100)
                self.analysis_completed.emit(results)
                self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] 전체 분석 완료")
        except Exception as e:
            error_msg = f"분석 실행 중 오류: {str(e)}"
            self.analysis_failed.emit(error_msg)
            self.log_message.emit(f"[{datetime.now().strftime('%H:%M:%S')}] {error_msg}")
    
    def cancel(self):
        """분석 취소"""
        self.is_cancelled = True


class ExtendedFactoryResetGUI(QMainWindow):
    """확장된 공장초기화 아티팩트 분석기 GUI"""
    
    def __init__(self):
        super().__init__()
        self.analysis_results = {}
        self.comparison_results = {}
        self.worker_thread = None
        self.initUI()
        
    def initUI(self):
        """UI 초기화"""
        self.setWindowTitle('확장된 공장초기화 아티팩트 분석기 v2.0')
        self.setGeometry(100, 100, 1400, 900)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        settings_frame = self.create_settings_panel()
        main_layout.addWidget(settings_frame)
        progress_frame = self.create_progress_panel()
        main_layout.addWidget(progress_frame)
        splitter = QSplitter(Qt.Horizontal)
        self.results_tab_widget = self.create_results_tabs()
        splitter.addWidget(self.results_tab_widget)
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter)
        self.statusBar().showMessage('준비')
        
    def create_settings_panel(self) -> QFrame:
        """설정 패널 생성"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setMaximumHeight(200)
        layout = QVBoxLayout()
        frame.setLayout(layout)
        title_label = QLabel("🔬 확장된 공장초기화 아티팩트 분석기")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        source_group = QGroupBox("분석 소스 선택")
        source_layout = QVBoxLayout()
        source_type_layout = QHBoxLayout()
        self.source_type_group = QButtonGroup()
        self.radio_zip = QRadioButton("ZIP 파일")
        self.radio_folder = QRadioButton("추출된 폴더")
        self.radio_adb = QRadioButton("ADB 연결")
        self.radio_zip.setChecked(True)
        self.source_type_group.addButton(self.radio_zip, 0)
        self.source_type_group.addButton(self.radio_folder, 1)
        self.source_type_group.addButton(self.radio_adb, 2)
        source_type_layout.addWidget(self.radio_zip)
        source_type_layout.addWidget(self.radio_folder)
        source_type_layout.addWidget(self.radio_adb)
        source_type_layout.addStretch()
        source_layout.addLayout(source_type_layout)
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("분석할 ZIP 파일 또는 폴더 경로를 선택하세요...")
        self.browse_button = QPushButton("찾아보기")
        self.browse_button.clicked.connect(self.browse_source)
        path_layout.addWidget(QLabel("경로:"))
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_button)
        source_layout.addLayout(path_layout)
        self.radio_zip.toggled.connect(self.on_source_type_changed)
        self.radio_folder.toggled.connect(self.on_source_type_changed)
        self.radio_adb.toggled.connect(self.on_source_type_changed)
        source_group.setLayout(source_layout)
        layout.addWidget(source_group)
        analysis_group = QGroupBox("분석 옵션")
        analysis_layout = QGridLayout()
        self.analysis_options = {
            "metadata": ("📁 파일 메타데이터", "파일 생성/수정 시간 분석"),
            "extended_logs": ("📝 확장 로그", "ANR, Tombstone, Dropbox 로그"),
            "databases": ("🗃️ 데이터베이스", "Settings, Usage Stats, Accounts"),
            "patterns": ("🔍 패턴 검색", "확장된 타임스탬프 패턴"),
            "binary": ("🔧 바이너리", "HEX 타임스탬프, 파일 시그니처"),
            "correlation": ("📊 상관관계", "타임스탬프 클러스터링, 이상치 탐지"),
            "timeline": ("⏰ 타임라인", "공장초기화 과정 재구성")
        }
        self.analysis_checkboxes = {}
        row, col = 0, 0
        for key, (name, desc) in self.analysis_options.items():
            checkbox = QCheckBox(name)
            checkbox.setToolTip(desc)
            checkbox.setChecked(True)
            self.analysis_checkboxes[key] = checkbox
            analysis_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        button_layout = QHBoxLayout()
        self.analyze_button = QPushButton("🚀 확장 분석 시작")
        self.analyze_button.setMinimumHeight(35)
        self.analyze_button.clicked.connect(self.start_analysis)
        self.cancel_button = QPushButton("⏹️ 분석 취소")
        self.cancel_button.setMinimumHeight(35)
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_analysis)
        self.load_basic_button = QPushButton("📋 기존 결과 로드")
        self.load_basic_button.setMinimumHeight(35)
        self.load_basic_button.clicked.connect(self.load_basic_results)
        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addStretch()
        button_layout.addWidget(self.load_basic_button)
        layout.addLayout(button_layout)
        return frame
    
    def create_progress_panel(self) -> QFrame:
        """진행률 표시 패널 생성"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setMaximumHeight(80)
        layout = QVBoxLayout()
        frame.setLayout(layout)
        self.progress_label = QLabel("분석 준비")
        layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        return frame
    
    def create_results_tabs(self) -> QTabWidget:
        """결과 탭 위젯 생성"""
        tab_widget = QTabWidget()
        self.result_tabs = {}
        tab_info = {
            "metadata": ("📁 메타데이터", self.create_metadata_tab),
            "extended_logs": ("📝 확장 로그", self.create_logs_tab),
            "databases": ("🗃️ 데이터베이스", self.create_database_tab),
            "patterns": ("🔍 패턴 검색", self.create_patterns_tab),
            "binary": ("🔧 바이너리", self.create_binary_tab),
            "correlation": ("📊 상관관계", self.create_correlation_tab),
            "timeline": ("⏰ 타임라인", self.create_timeline_tab),
            "comparison": ("⚖️ 비교분석", self.create_comparison_tab),
            "summary": ("📋 종합요약", self.create_summary_tab)
        }
        for key, (name, create_func) in tab_info.items():
            tab = create_func()
            tab_widget.addTab(tab, name)
            self.result_tabs[key] = tab
        return tab_widget
    
    def create_metadata_tab(self) -> QWidget:
        """메타데이터 분석 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["파일 경로", "크기", "수정 시간", "생성 시간", "공장초기화 관련", "비고"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        layout.addWidget(table)
        self.metadata_table = table
        return widget
    
    def create_logs_tab(self) -> QWidget:
        """확장 로그 분석 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        sub_tab_widget = QTabWidget()
        log_types = ["ANR 로그", "Tombstone", "Dropbox", "Kernel", "Logcat"]
        self.log_tables = {}
        for log_type in log_types:
            table = QTableWidget()
            table.setColumnCount(4)
            table.setHorizontalHeaderLabels(["파일", "타임스탬프", "내용 미리보기", "상세정보"])
            header = table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.Stretch)
            sub_tab_widget.addTab(table, log_type)
            self.log_tables[log_type.lower().replace(" ", "_")] = table
        layout.addWidget(sub_tab_widget)
        return widget
    
    def create_database_tab(self) -> QWidget:
        """데이터베이스 분석 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        sub_tab_widget = QTabWidget()
        db_types = ["Settings", "Usage Stats", "Accounts", "Package"]
        self.db_tables = {}
        for db_type in db_types:
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["키/항목", "값", "관련성"])
            header = table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.Stretch)
            sub_tab_widget.addTab(table, db_type)
            self.db_tables[db_type.lower().replace(" ", "_")] = table
        layout.addWidget(sub_tab_widget)
        return widget
    
    def create_patterns_tab(self) -> QWidget:
        """패턴 검색 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["패턴 유형", "파일", "매칭 내용", "위치", "컨텍스트"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(table)
        self.patterns_table = table
        return widget
    
    def create_binary_tab(self) -> QWidget:
        """바이너리 분석 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["파일", "오프셋", "HEX 값", "타임스탬프", "변환된 시간", "신뢰도"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(table)
        self.binary_table = table
        return widget
    
    def create_correlation_tab(self) -> QWidget:
        """상관관계 분석 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        sub_tab_widget = QTabWidget()
        correlation_types = ["클러스터", "이상치", "일관성", "누락구간"]
        self.correlation_tables = {}
        for corr_type in correlation_types:
            table = QTableWidget()
            if corr_type == "클러스터":
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(["시작시간", "종료시간", "이벤트 수", "설명"])
            elif corr_type == "이상치":
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["타임스탬프", "이상 유형", "설명"])
            header = table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.Stretch)
            sub_tab_widget.addTab(table, corr_type)
            self.correlation_tables[corr_type] = table
        layout.addWidget(sub_tab_widget)
        return widget
    
    def create_timeline_tab(self) -> QWidget:
        """타임라인 재구성 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        confidence_layout = QHBoxLayout()
        self.confidence_label = QLabel("타임라인 재구성 신뢰도: 계산 중...")
        confidence_layout.addWidget(self.confidence_label)
        confidence_layout.addStretch()
        layout.addLayout(confidence_layout)
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["단계", "시간", "이벤트", "소스", "설명"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(table)
        self.timeline_table = table
        return widget
    
    def create_comparison_tab(self) -> QWidget:
        """기존 분석과 비교 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        summary_group = QGroupBox("비교 요약")
        summary_layout = QGridLayout()
        self.comparison_labels = {
            "basic_count": QLabel("기존 분석: 계산 중..."),
            "extended_count": QLabel("확장 분석: 계산 중..."),
            "improvement": QLabel("개선율: 계산 중..."),
            "confidence": QLabel("신뢰도: 계산 중...")
        }
        row = 0
        for key, label in self.comparison_labels.items():
            summary_layout.addWidget(label, row, 0)
            row += 1
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["분석 유형", "기존 결과", "확장 결과", "개선사항"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(table)
        self.comparison_table = table
        return widget
    
    def create_summary_tab(self) -> QWidget:
        """종합 요약 탭"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_text)
        export_layout = QHBoxLayout()
        self.export_json_button = QPushButton("📄 JSON으로 내보내기")
        self.export_json_button.clicked.connect(self.export_results_json)
        self.export_report_button = QPushButton("📊 리포트 생성")
        self.export_report_button.clicked.connect(self.generate_report)
        export_layout.addWidget(self.export_json_button)
        export_layout.addWidget(self.export_report_button)
        export_layout.addStretch()
        layout.addLayout(export_layout)
        return widget
    
    def create_right_panel(self) -> QWidget:
        """우측 패널 (로그 및 상태) 생성"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        log_group = QGroupBox("실행 로그")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(300)
        self.log_text.setReadOnly(True)
        clear_log_button = QPushButton("로그 지우기")
        clear_log_button.clicked.connect(self.clear_log)
        log_layout.addWidget(self.log_text)
        log_layout.addWidget(clear_log_button)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        status_group = QGroupBox("분석 상태")
        status_layout = QVBoxLayout()
        self.status_labels = {
            "total_artifacts": QLabel("발견된 아티팩트: 0개"),
            "processing_time": QLabel("처리 시간: --"),
            "current_analysis": QLabel("현재 분석: 대기 중"),
            "memory_usage": QLabel("메모리 사용량: --")
        }
        for label in self.status_labels.values():
            status_layout.addWidget(label)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        layout.addStretch()
        return widget
    
    def on_source_type_changed(self):
        """소스 타입 변경 시 처리"""
        if self.radio_adb.isChecked():
            self.path_edit.setPlaceholderText("ADB 모드 - 연결된 기기를 분석합니다")
            self.path_edit.setEnabled(False)
            self.browse_button.setEnabled(False)
        else:
            self.path_edit.setEnabled(True)
            self.browse_button.setEnabled(True)
            if self.radio_zip.isChecked():
                self.path_edit.setPlaceholderText("ZIP 파일 경로를 선택하세요...")
            else:
                self.path_edit.setPlaceholderText("추출된 폴더 경로를 선택하세요...")
    
    def browse_source(self):
        """소스 파일/폴더 선택"""
        if self.radio_zip.isChecked():
            file_path, _ = QFileDialog.getOpenFileName(self, "ZIP 파일 선택", "", "ZIP 파일 (*.zip)")
            if file_path:
                self.path_edit.setText(file_path)
        else:
            folder_path = QFileDialog.getExistingDirectory(self, "폴더 선택")
            if folder_path:
                self.path_edit.setText(folder_path)
    
    def load_basic_results(self):
        """기존 분석 결과 로드"""
        file_path, _ = QFileDialog.getOpenFileName(self, "기존 분석 결과 파일 선택", "", "JSON 파일 (*.json)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    basic_results = json.load(f)
                self.log_message(f"기존 분석 결과 로드 완료: {len(basic_results)}개 항목")
                QMessageBox.information(self, "로드 완료", f"기존 분석 결과를 성공적으로 로드했습니다.\n{len(basic_results)}개 항목")
            except Exception as e:
                error_msg = f"파일 로드 실패: {str(e)}"
                self.log_message(error_msg)
                QMessageBox.warning(self, "로드 실패", error_msg)
    
    def start_analysis(self):
        """분석 시작"""
        if self.radio_adb.isChecked():
            source_path = ""
            source_type = "adb"
        else:
            source_path = self.path_edit.text().strip()
            if not source_path:
                QMessageBox.warning(self, "입력 오류", "분석할 파일 또는 폴더를 선택하세요.")
                return
            if not os.path.exists(source_path):
                QMessageBox.warning(self, "경로 오류", "선택한 경로가 존재하지 않습니다.")
                return
            source_type = "zip" if self.radio_zip.isChecked() else "folder"
        selected_analyses = []
        for key, checkbox in self.analysis_checkboxes.items():
            if checkbox.isChecked():
                selected_analyses.append(key)
        if not selected_analyses:
            QMessageBox.warning(self, "선택 오류", "최소 하나의 분석 옵션을 선택하세요.")
            return
        self.analyze_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.clear_all_results()
        self.worker_thread = ExtendedAnalysisWorkerThread(source_path, source_type, selected_analyses)
        self.worker_thread.analysis_started.connect(self.on_analysis_started)
        self.worker_thread.progress_updated.connect(self.on_progress_updated)
        self.worker_thread.category_completed.connect(self.on_category_completed)
        self.worker_thread.analysis_completed.connect(self.on_analysis_completed)
        self.worker_thread.analysis_failed.connect(self.on_analysis_failed)
        self.worker_thread.log_message.connect(self.log_message)
        self.worker_thread.start()
        self.start_time = datetime.now()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_processing_time)
        self.timer.start(1000)
    
    def cancel_analysis(self):
        """분석 취소"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.cancel()
            self.worker_thread.wait(3000)
            self.log_message("분석이 사용자에 의해 취소되었습니다.")
        self.reset_ui_state()
    
    def reset_ui_state(self):
        """UI 상태 리셋"""
        self.analyze_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("분석 준비")
        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()
    
    def on_analysis_started(self, message):
        """분석 시작 시 처리"""
        self.log_message(message)
        self.statusBar().showMessage("분석 진행 중...")
    
    def on_progress_updated(self, message, progress):
        """진행률 업데이트"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(progress)
        self.status_labels["current_analysis"].setText(f"현재 분석: {message}")
    
    def on_category_completed(self, category, results):
        """카테고리별 분석 완료 시 결과 표시"""
        try:
            if category == "metadata":
                self.display_metadata_results(results)
            elif category == "extended_logs":
                self.display_logs_results(results)
            elif category == "databases":
                self.display_database_results(results)
            elif category == "patterns":
                self.display_patterns_results(results)
            elif category == "binary":
                self.display_binary_results(results)
            elif category == "correlation":
                self.display_correlation_results(results)
            elif category == "timeline":
                self.display_timeline_results(results)
        except Exception as e:
            self.log_message(f"결과 표시 오류 ({category}): {str(e)}")
    
    def on_analysis_completed(self, results):
        """전체 분석 완료"""
        self.analysis_results = results
        self.display_summary_results(results.get("summary", {}))
        self.perform_comparison_analysis()
        self.reset_ui_state()
        summary = results.get("summary", {})
        total_artifacts = summary.get("total_artifacts_found", 0)
        new_timestamps = summary.get("new_timestamp_sources", 0)
        completion_msg = (f"확장 분석이 완료되었습니다!\n\n"
                         f"🔍 발견된 아티팩트: {total_artifacts}개\n"
                         f"⏰ 새로운 타임스탬프: {new_timestamps}개\n"
                         f"📊 신뢰도: {summary.get('confidence_level', 'unknown')}")
        QMessageBox.information(self, "분석 완료", completion_msg)
        self.statusBar().showMessage(f"분석 완료 - {total_artifacts}개 아티팩트 발견")
    
    def on_analysis_failed(self, error_message):
        """분석 실패 처리"""
        self.log_message(f"분석 실패: {error_message}")
        QMessageBox.critical(self, "분석 실패", f"분석 중 오류가 발생했습니다:\n\n{error_message}")
        self.reset_ui_state()
    
    def display_metadata_results(self, results):
        """메타데이터 분석 결과 표시"""
        table = self.metadata_table
        files_data = []
        if "zip_files" in results:
            files_data.extend(results["zip_files"])
        if "folder_files" in results:
            files_data.extend(results["folder_files"])
        if "adb_files" in results:
            files_data.extend(results["adb_files"])
        table.setRowCount(len(files_data))
        for row, file_info in enumerate(files_data):
            table.setItem(row, 0, QTableWidgetItem(file_info.get("path", "")))
            table.setItem(row, 1, QTableWidgetItem(str(file_info.get("size", ""))))
            mod_time = file_info.get("modification_time", "")
            if isinstance(mod_time, datetime):
                mod_time = mod_time.strftime("%Y-%m-%d %H:%M:%S")
            table.setItem(row, 2, QTableWidgetItem(str(mod_time)))
            create_time = file_info.get("creation_time", "")
            if isinstance(create_time, datetime):
                create_time = create_time.strftime("%Y-%m-%d %H:%M:%S")
            table.setItem(row, 3, QTableWidgetItem(str(create_time)))
            is_related = "✓" if file_info.get("factory_reset_related", False) else ""
            table.setItem(row, 4, QTableWidgetItem(is_related))
            table.setItem(row, 5, QTableWidgetItem(file_info.get("notes", "")))
    
    def display_logs_results(self, results):
        """로그 분석 결과 표시"""
        log_mapping = {"anr_logs": "anr_로그", "tombstone_logs": "tombstone", "dropbox_logs": "dropbox",
                      "kernel_logs": "kernel", "logcat_archives": "logcat"}
        for log_type, table_key in log_mapping.items():
            if log_type in results and table_key in self.log_tables:
                logs = results[log_type]
                table = self.log_tables[table_key]
                table.setRowCount(len(logs))
                for row, log_info in enumerate(logs):
                    table.setItem(row, 0, QTableWidgetItem(log_info.get("file", "")))
                    timestamp = log_info.get("timestamp", log_info.get("crash_time", ""))
                    if isinstance(timestamp, datetime):
                        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    table.setItem(row, 1, QTableWidgetItem(str(timestamp)))
                    preview = log_info.get("content_preview", "")[:100]
                    table.setItem(row, 2, QTableWidgetItem(preview))
                    details = str(log_info.get("timestamps", log_info.get("setup_logs", "")))
                    table.setItem(row, 3, QTableWidgetItem(details[:200]))
    
    def display_database_results(self, results):
        """데이터베이스 분석 결과 표시"""
        db_mapping = {"settings_db": "settings", "usage_stats": "usage_stats", "accounts_db": "accounts",
                     "package_db": "package"}
        for db_type, table_key in db_mapping.items():
            if db_type in results and table_key in self.db_tables:
                db_data = results[db_type]
                table = self.db_tables[table_key]
                if db_type == "settings_db" and "queries" in db_data:
                    all_rows = []
                    for query_result in db_data["queries"].values():
                        if "rows" in query_result:
                            for row in query_result["rows"]:
                                all_rows.append({"key": str(row[0]) if len(row) > 0 else "",
                                               "value": str(row[1]) if len(row) > 1 else "",
                                               "relation": "설정 항목"})
                    table.setRowCount(len(all_rows))
                    for row, item in enumerate(all_rows):
                        table.setItem(row, 0, QTableWidgetItem(item["key"]))
                        table.setItem(row, 1, QTableWidgetItem(item["value"]))
                        table.setItem(row, 2, QTableWidgetItem(item["relation"]))
                elif db_type == "usage_stats" and isinstance(db_data, list):
                    all_items = []
                    for stat_file in db_data:
                        stats = stat_file.get("stats", {})
                        for package in stats.get("packages", []):
                            all_items.append({"key": package.get("name", ""),
                                            "value": f"마지막 사용: {package.get('last_used', '')}",
                                            "relation": "앱 사용"})
                    table.setRowCount(len(all_items))
                    for row, item in enumerate(all_items):
                        table.setItem(row, 0, QTableWidgetItem(item["key"]))
                        table.setItem(row, 1, QTableWidgetItem(item["value"]))
                        table.setItem(row, 2, QTableWidgetItem(item["relation"]))
    
    def display_patterns_results(self, results):
        """패턴 검색 결과 표시"""
        table = self.patterns_table
        all_matches = []
        for pattern_name, matches in results.items():
            for match in matches:
                all_matches.append({"pattern": pattern_name, "file": match.get("file", ""),
                                  "match": match.get("match", ""), "position": str(match.get("position", "")),
                                  "context": match.get("context", "")})
        table.setRowCount(len(all_matches))
        for row, match in enumerate(all_matches):
            table.setItem(row, 0, QTableWidgetItem(match["pattern"]))
            table.setItem(row, 1, QTableWidgetItem(match["file"]))
            table.setItem(row, 2, QTableWidgetItem(match["match"]))
            table.setItem(row, 3, QTableWidgetItem(match["position"]))
            table.setItem(row, 4, QTableWidgetItem(match["context"]))
    
    def display_binary_results(self, results):
        """바이너리 분석 결과 표시"""
        table = self.binary_table
        hex_timestamps = results.get("hex_timestamps", [])
        table.setRowCount(len(hex_timestamps))
        for row, hex_ts in enumerate(hex_timestamps):
            table.setItem(row, 0, QTableWidgetItem(hex_ts.get("file", "")))
            table.setItem(row, 1, QTableWidgetItem(str(hex_ts.get("offset", ""))))
            table.setItem(row, 2, QTableWidgetItem(hex_ts.get("hex_value", "")))
            table.setItem(row, 3, QTableWidgetItem(str(hex_ts.get("timestamp", ""))))
            dt = hex_ts.get("datetime")
            if isinstance(dt, datetime):
                dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                dt_str = str(dt)
            table.setItem(row, 4, QTableWidgetItem(dt_str))
            table.setItem(row, 5, QTableWidgetItem("높음"))
    
    def display_correlation_results(self, results):
        """상관관계 분석 결과 표시"""
        if "clusters" in results:
            clusters = results["clusters"]
            table = self.correlation_tables.get("클러스터")
            if table:
                table.setRowCount(len(clusters))
                for row, cluster in enumerate(clusters):
                    start_time = cluster.get("start_time")
                    if isinstance(start_time, datetime):
                        start_time = start_time.strftime("%Y-%m-%d %H:%M:%S")
                    end_time = cluster.get("end_time")
                    if isinstance(end_time, datetime):
                        end_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
                    table.setItem(row, 0, QTableWidgetItem(str(start_time)))
                    table.setItem(row, 1, QTableWidgetItem(str(end_time)))
                    table.setItem(row, 2, QTableWidgetItem(str(cluster.get("count", 0))))
                    table.setItem(row, 3, QTableWidgetItem("타임스탬프 클러스터"))
        if "outliers" in results:
            outliers = results["outliers"]
            table = self.correlation_tables.get("이상치")
            if table:
                table.setRowCount(len(outliers))
                for row, outlier in enumerate(outliers):
                    timestamp = outlier.get("timestamp", {})
                    if isinstance(timestamp, dict):
                        ts_dt = timestamp.get("datetime")
                        if isinstance(ts_dt, datetime):
                            ts_str = ts_dt.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            ts_str = str(ts_dt)
                    else:
                        ts_str = str(timestamp)
                    table.setItem(row, 0, QTableWidgetItem(ts_str))
                    table.setItem(row, 1, QTableWidgetItem(outlier.get("reason", "")))
                    table.setItem(row, 2, QTableWidgetItem(f"시간 간격: {outlier.get('interval', 0):.2f}초"))
    
    def display_timeline_results(self, results):
        """타임라인 재구성 결과 표시"""
        table = self.timeline_table
        confidence = results.get("reconstruction_confidence", 0)
        self.confidence_label.setText(f"타임라인 재구성 신뢰도: {confidence:.1%}")
        timeline_events = []
        for event in results.get("pre_reset", []):
            timeline_events.append({"stage": "이전", "datetime": event.get("datetime"),
                                  "event": event.get("description", ""), "source": event.get("source", ""),
                                  "details": event.get("details", "")})
        for event in results.get("reset_process", []):
            timeline_events.append({"stage": "진행", "datetime": event.get("datetime"),
                                  "event": event.get("description", ""), "source": event.get("source", ""),
                                  "details": event.get("details", "")})
        for event in results.get("post_reset", []):
            timeline_events.append({"stage": "이후", "datetime": event.get("datetime"),
                                  "event": event.get("description", ""), "source": event.get("source", ""),
                                  "details": event.get("details", "")})
        timeline_events.sort(key=lambda x: x.get("datetime", datetime.min))
        table.setRowCount(len(timeline_events))
        for row, event in enumerate(timeline_events):
            table.setItem(row, 0, QTableWidgetItem(event["stage"]))
            dt = event["datetime"]
            if isinstance(dt, datetime):
                dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                dt_str = str(dt)
            table.setItem(row, 1, QTableWidgetItem(dt_str))
            table.setItem(row, 2, QTableWidgetItem(event["event"]))
            table.setItem(row, 3, QTableWidgetItem(event["source"]))
            table.setItem(row, 4, QTableWidgetItem(event["details"]))
    
    def display_summary_results(self, summary):
        """요약 결과 표시"""
        summary_text = f"""📊 확장 분석 완료 요약

🔍 발견된 아티팩트: {summary.get('total_artifacts_found', 0)}개
⏰ 새로운 타임스탬프 소스: {summary.get('new_timestamp_sources', 0)}개  
📈 신뢰도 레벨: {summary.get('confidence_level', 'unknown')}

🔑 주요 발견사항:
"""
        for finding in summary.get('key_findings', []):
            summary_text += f"• {finding}\n"
        summary_text += "\n💡 권장사항:\n"
        for recommendation in summary.get('recommendations', []):
            summary_text += f"• {recommendation}\n"
        self.summary_text.setPlainText(summary_text)
        self.status_labels["total_artifacts"].setText(f"발견된 아티팩트: {summary.get('total_artifacts_found', 0)}개")
    
    def perform_comparison_analysis(self):
        """기존 분석과 비교 분석 수행"""
        extended_count = self.analysis_results.get("summary", {}).get("total_artifacts_found", 0)
        self.comparison_labels["extended_count"].setText(f"확장 분석: {extended_count}개")
        self.comparison_labels["basic_count"].setText("기존 분석: 미로드")
        self.comparison_labels["improvement"].setText("개선율: 계산 불가")
        self.comparison_labels["confidence"].setText("신뢰도: 중간")
    
    def clear_all_results(self):
        """모든 결과 테이블 초기화"""
        tables = [self.metadata_table, self.patterns_table, self.binary_table, self.timeline_table, self.comparison_table]
        for table in self.log_tables.values():
            tables.append(table)
        for table in self.db_tables.values():
            tables.append(table)
        for table in self.correlation_tables.values():
            tables.append(table)
        for table in tables:
            if table:
                table.setRowCount(0)
        self.summary_text.clear()
    
    def update_processing_time(self):
        """처리 시간 업데이트"""
        if hasattr(self, 'start_time'):
            elapsed = datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]
            self.status_labels["processing_time"].setText(f"처리 시간: {elapsed_str}")
    
    def log_message(self, message):
        """로그 메시지 추가"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.append(formatted_message)
        cursor = self.log_text.textCursor()
        cursor.movePosition(cursor.End)
        self.log_text.setTextCursor(cursor)
    
    def clear_log(self):
        """로그 지우기"""
        self.log_text.clear()
    
    def export_results_json(self):
        """결과를 JSON으로 내보내기"""
        if not self.analysis_results:
            QMessageBox.warning(self, "내보내기 오류", "내보낼 분석 결과가 없습니다.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "분석 결과 저장",
                                                  f"extended_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                                  "JSON 파일 (*.json)")
        if file_path:
            try:
                def json_serializer(obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    elif isinstance(obj, bytes):
                        return obj.hex()
                    return str(obj)
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, ensure_ascii=False, indent=2, default=json_serializer)
                QMessageBox.information(self, "저장 완료", f"분석 결과가 저장되었습니다.\n{file_path}")
                self.log_message(f"분석 결과 JSON 저장 완료: {file_path}")
            except Exception as e:
                error_msg = f"저장 실패: {str(e)}"
                QMessageBox.warning(self, "저장 실패", error_msg)
                self.log_message(error_msg)
    
    def generate_report(self):
        """분석 리포트 생성"""
        if not self.analysis_results:
            QMessageBox.warning(self, "리포트 오류", "리포트를 생성할 분석 결과가 없습니다.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "분석 리포트 저장",
                                                  f"extended_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                                  "텍스트 파일 (*.txt)")
        if file_path:
            try:
                summary = self.analysis_results.get("summary", {})
                report_content = f"""
=============================================================
확장된 공장초기화 아티팩트 분석 리포트
=============================================================

생성일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
분석 대상: {self.path_edit.text() if not self.radio_adb.isChecked() else 'ADB 연결 기기'}
분석 모드: {'ZIP 파일' if self.radio_zip.isChecked() else '폴더' if self.radio_folder.isChecked() else 'ADB'}

📊 분석 요약
=============================================================
🔍 총 발견된 아티팩트: {summary.get('total_artifacts_found', 0)}개
⏰ 새로운 타임스탬프 소스: {summary.get('new_timestamp_sources', 0)}개
📈 신뢰도 레벨: {summary.get('confidence_level', 'unknown')}

🔑 주요 발견사항:
"""
                for finding in summary.get('key_findings', []):
                    report_content += f"• {finding}\n"
                report_content += "\n💡 권장사항:\n"
                for recommendation in summary.get('recommendations', []):
                    report_content += f"• {recommendation}\n"
                for category, data in self.analysis_results.items():
                    if category != "summary" and data:
                        report_content += f"\n📂 {category.upper()} 분석 결과:\n"
                        if isinstance(data, dict):
                            for key, value in data.items():
                                if isinstance(value, list):
                                    report_content += f"  - {key}: {len(value)}개 항목\n"
                                else:
                                    report_content += f"  - {key}: {str(value)[:100]}\n"
                report_content += f"""
=============================================================
리포트 생성 완료 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=============================================================
"""
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                QMessageBox.information(self, "리포트 생성 완료", f"분석 리포트가 생성되었습니다.\n{file_path}")
                self.log_message(f"분석 리포트 생성 완료: {file_path}")
            except Exception as e:
                error_msg = f"리포트 생성 실패: {str(e)}"
                QMessageBox.warning(self, "생성 실패", error_msg)
                self.log_message(error_msg)


def main():
    """메인 실행 함수"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("확장된 공장초기화 아티팩트 분석기")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Digital Forensics Lab")
    window = ExtendedFactoryResetGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

