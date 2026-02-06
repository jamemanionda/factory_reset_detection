import io
import re
import subprocess
import zipfile
import os
import sys
import struct
import html
import json
import logging
import traceback
from datetime import datetime, timedelta

# Filter PyQt5 warning messages (ignore QTableWidget sorting-related warnings)
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.qobject.connect.warning=false;qt.qobject.connect=false'

import pandas as pd
from pyaxmlparser import APK
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QRadioButton, 
                             QButtonGroup, QCheckBox, QTextEdit, QFileDialog,
                             QGroupBox, QLineEdit, QMessageBox, QProgressBar,
                             QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                             QDialog, QInputDialog, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QComboBox, QSizePolicy, QMenu)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, qInstallMessageHandler
from PyQt5.QtGui import QTextDocument, QTextCursor, QClipboard

# sqlite3 is lazy imported (prevent DLL issues)


class CopyableMessageBox(QDialog):
    """Message box with copyable text"""
    def __init__(self, parent, title, message, icon_type="information"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(400)
        self.setMinimumHeight(200)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Message text (selectable)
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(message)
        self.text_edit.setReadOnly(True)
        self.text_edit.setMaximumHeight(300)
        layout.addWidget(self.text_edit)
        
        # Button area
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Copy button
        btn_copy = QPushButton("Copy")
        btn_copy.clicked.connect(self.copy_text)
        button_layout.addWidget(btn_copy)
        
        # OK button
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_ok.setDefault(True)
        button_layout.addWidget(btn_ok)
        
        layout.addLayout(button_layout)
    
    def copy_text(self):
        """Copy text to clipboard"""
        try:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.text_edit.toPlainText())
            # Simple notification only (prevent infinite loop)
            self.text_edit.setPlaceholderText("Text copied to clipboard.")
        except Exception as e:
            pass  # Silently handle copy failure


class WorkerThread(QThread):
    """Thread for background tasks"""
    finished = pyqtSignal()
    output = pyqtSignal(str)
    
    def __init__(self, reset_instance):
        super().__init__()
        self.reset_instance = reset_instance
    
    def run(self):
        try:
            self.reset_instance.run_analysis()
        except Exception as e:
            self.output.emit(f"Error occurred: {str(e)}\n")
        finally:
            self.finished.emit()


class DeepSearchThread(QThread):
    """Thread for deep search"""
    finished = pyqtSignal()
    result_found = pyqtSignal(str, str, str, str)  # search_time_str, file_path, match_format, match_value
    progress_updated = pyqtSignal(int, int)  # current, total
    
    def __init__(self, reset_instance, search_times, gui_instance, time_tolerance_seconds=300):
        super().__init__()
        self.reset_instance = reset_instance
        self.search_times = search_times
        self.gui_instance = gui_instance
        self.time_tolerance_seconds = time_tolerance_seconds
    
    def run(self):
        try:
            self.reset_instance.deep_search(self.search_times, self.result_found, self.progress_updated, self.time_tolerance_seconds)
        except Exception as e:
            if self.reset_instance:
                self.reset_instance.log(f"Error occurred during deep search: {str(e)}\n")
        finally:
            self.finished.emit()


class FactoryResetGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.reset_instance = None
        self.artifact_data = {}  # Store data for each artifact
        self.use_kst = True  # Default is KST
        self.analysis_running = False  # Whether analysis is running
        self.selected_artifacts = []  # Selected artifact list
        self.confirmed_time_value = None
        self.confirmed_time_dt = None
        self.artifact_tables = {}
        self.saved_file_path = None  # File path of saved result
        self.saved_source = None  # Source of saved result (ZIP, ADB, Folder)
        self.hidden_artifacts = set()  # Hidden artifact list
        self.hidden_items = {}  # Hidden items: {artifact_id: set(item_keys)}
        self.init_ui()
    
    def show_message(self, title, message, icon_type="information"):
        """Show copyable message box"""
        try:
            msg_box = CopyableMessageBox(self, title, message, icon_type)
            msg_box.exec_()
        except Exception as e:
            # Use default QMessageBox on error
            try:
                QMessageBox.information(self, title, message)
            except:
                pass
    
    def show_question(self, title, message):
        """Question message box (Yes/No) - copyable"""
        try:
            # Custom dialog for questions
            dialog = QDialog(self)
            dialog.setWindowTitle(title)
            dialog.setMinimumWidth(400)
            dialog.setMinimumHeight(200)
            
            layout = QVBoxLayout()
            dialog.setLayout(layout)
            
            # Message text (selectable)
            text_edit = QTextEdit()
            text_edit.setPlainText(message)
            text_edit.setReadOnly(True)
            text_edit.setMaximumHeight(300)
            layout.addWidget(text_edit)
            
            # Button area
            button_layout = QHBoxLayout()
            button_layout.addStretch()
            
            # Copy button
            btn_copy = QPushButton("Copy")
            def copy_text():
                try:
                    clipboard = QApplication.clipboard()
                    clipboard.setText(text_edit.toPlainText())
                except:
                    pass
            btn_copy.clicked.connect(copy_text)
            button_layout.addWidget(btn_copy)
            
            # Yes/No buttons
            btn_yes = QPushButton("Yes")
            btn_yes.clicked.connect(dialog.accept)
            button_layout.addWidget(btn_yes)
            
            btn_no = QPushButton("No")
            btn_no.clicked.connect(dialog.reject)
            button_layout.addWidget(btn_no)
            
            layout.addLayout(button_layout)
            
            if dialog.exec_() == QDialog.Accepted:
                return QMessageBox.Yes
            return QMessageBox.No
        except Exception:
            # Use default QMessageBox on error
            try:
                return QMessageBox.question(self, title, message, QMessageBox.Yes | QMessageBox.No)
            except:
                return QMessageBox.No
    
    def init_ui(self):
        self.setWindowTitle('Factory Reset Artifact Analyzer')
        self.setGeometry(100, 100, 900, 700)
        
        # 중앙 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout - split left/right (left: controls+results, right: log)
        main_splitter = QSplitter(Qt.Horizontal)
        central_widget.setLayout(QVBoxLayout())
        central_widget.layout().addWidget(main_splitter)
        
        # Left area (controls + results)
        left_widget = QWidget()
        main_layout = QVBoxLayout()
        left_widget.setLayout(main_layout)
        
        # Search target selection group
        source_group = QGroupBox("Search Target")
        source_layout = QVBoxLayout()
        self.source_buttons = QButtonGroup()
        
        self.radio_zip = QRadioButton("1. ZIP file")
        self.radio_adb = QRadioButton("2. live device using adb")
        self.radio_folder = QRadioButton("3. Extracted folder (unzipped folder)")
        
        self.source_buttons.addButton(self.radio_zip, 1)
        self.source_buttons.addButton(self.radio_adb, 2)
        self.source_buttons.addButton(self.radio_folder, 3)
        
        source_layout.addWidget(self.radio_zip)
        source_layout.addWidget(self.radio_adb)
        source_layout.addWidget(self.radio_folder)
        source_group.setLayout(source_layout)
        
        # Search target group size fixed (width flexible, height fixed)
        source_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        source_group.setFixedHeight(100)  # Only height fixed
        
        main_layout.addWidget(source_group)
        
        # File/folder selection area
        file_group = QGroupBox("File/Folder Selection")
        file_layout = QVBoxLayout()
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select file or folder path...")
        self.file_path_edit.setReadOnly(True)
        
        file_button_layout = QHBoxLayout()
        self.btn_select_file = QPushButton("Select ZIP File")
        self.btn_select_folder = QPushButton("Select Folder")
        self.btn_select_file.clicked.connect(self.select_file)
        self.btn_select_folder.clicked.connect(self.select_folder)
        
        file_button_layout.addWidget(self.btn_select_file)
        file_button_layout.addWidget(self.btn_select_folder)
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addLayout(file_button_layout)
        file_group.setLayout(file_layout)
        
        # File/folder selection group size fixed (width flexible, height fixed)
        file_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        file_group.setFixedHeight(100)  # Only height fixed
        
        main_layout.addWidget(file_group)
        
        # Artifact selection group
        artifact_group = QGroupBox("Artifacts to Find")
        artifact_layout = QVBoxLayout()
        
        # All checkbox separately
        self.checkbox_all = QCheckBox("0. All (Select All)")
        self.checkbox_all.stateChanged.connect(self.toggle_all_artifacts)
        artifact_layout.addWidget(self.checkbox_all)
        
        # Remaining checkboxes in 3 columns
        checkbox_grid = QHBoxLayout()
        
        # First column
        column1 = QVBoxLayout()
        self.checkbox_bootstat = QCheckBox("1. bootstat")
        self.checkbox_recovery_log = QCheckBox("2-1. recovery.log")
        self.checkbox_last_log = QCheckBox("2-2. last_log")
        self.checkbox_suggestions = QCheckBox("3. suggestions.xml")
        column1.addWidget(self.checkbox_bootstat)
        column1.addWidget(self.checkbox_recovery_log)
        column1.addWidget(self.checkbox_last_log)
        column1.addWidget(self.checkbox_suggestions)
        checkbox_grid.addLayout(column1)
        
        # Second column
        column2 = QVBoxLayout()
        self.checkbox_persistent = QCheckBox("4. persistent_properties")
        self.checkbox_appops = QCheckBox("5. appops")
        self.checkbox_wellbing = QCheckBox("6. wellbing")
        self.checkbox_internal = QCheckBox("7. internal")
        column2.addWidget(self.checkbox_persistent)
        column2.addWidget(self.checkbox_appops)
        column2.addWidget(self.checkbox_wellbing)
        column2.addWidget(self.checkbox_internal)
        checkbox_grid.addLayout(column2)
        
        # Third column
        column3 = QVBoxLayout()
        self.checkbox_err = QCheckBox("8. eRR.p")
        self.checkbox_ulr = QCheckBox("9. ULR_PERSISTENT_PREFS.xml")
        column3.addWidget(self.checkbox_err)
        column3.addWidget(self.checkbox_ulr)
        column3.addStretch()  # Fill remaining space
        checkbox_grid.addLayout(column3)
        
        self.artifact_checkboxes = [
            self.checkbox_bootstat,
            self.checkbox_recovery_log,
            self.checkbox_last_log,
            self.checkbox_suggestions,
            self.checkbox_persistent,
            self.checkbox_appops,
            self.checkbox_wellbing,
            self.checkbox_internal,
            self.checkbox_err,
            self.checkbox_ulr
        ]
        
        # Checkbox to artifact_id mapping
        self.checkbox_to_artifact_id = {
            self.checkbox_bootstat: "1",
            self.checkbox_recovery_log: "21",
            self.checkbox_last_log: "22",
            self.checkbox_suggestions: "3",
            self.checkbox_persistent: "4",
            self.checkbox_appops: "5",
            self.checkbox_wellbing: "6",
            self.checkbox_internal: "7",
            self.checkbox_err: "8",
            self.checkbox_ulr: "9"
        }
        
        # Connect real-time filtering to each checkbox
        for checkbox in self.artifact_checkboxes:
            checkbox.stateChanged.connect(self.on_artifact_filter_changed)
        
        artifact_layout.addLayout(checkbox_grid)
        artifact_group.setLayout(artifact_layout)
        
        # Artifact group size fixed (width flexible, height fixed)
        artifact_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        artifact_group.setFixedHeight(180)  # Only height fixed
        
        main_layout.addWidget(artifact_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.clicked.connect(self.run_analysis)
        self.btn_run.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; }")
        
        self.btn_deep_search = QPushButton("Deep Search")
        self.btn_deep_search.clicked.connect(self.run_deep_search)
        self.btn_deep_search.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; padding: 10px; }")
        self.btn_deep_search.setEnabled(False)  # Enabled after analysis completes
        
        self.btn_view_saved = QPushButton("View Saved Results")
        self.btn_view_saved.clicked.connect(self.show_saved_results)
        self.btn_view_saved.setStyleSheet("QPushButton { background-color: #FF9800; color: white; font-weight: bold; padding: 10px; }")
        
        self.btn_item_settings = QPushButton("Item Visibility Settings")
        self.btn_item_settings.clicked.connect(self.show_item_visibility_settings)
        self.btn_item_settings.setStyleSheet("QPushButton { background-color: #9C27B0; color: white; font-weight: bold; padding: 10px; }")
        
        button_layout.addWidget(self.btn_run)
        button_layout.addWidget(self.btn_deep_search)
        button_layout.addWidget(self.btn_view_saved)
        button_layout.addWidget(self.btn_item_settings)
        main_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(30)  # Minimum height
        self.progress_bar.setMaximumHeight(30)  # Maximum height (fixed)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 3px;
                text-align: center;
                background-color: #f0f0f0;
                font-size: 10pt;
                padding: 2px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 2px;
            }
        """)
        main_layout.addWidget(self.progress_bar)
        
        # Timezone selection checkbox
        timezone_layout = QHBoxLayout()
        self.checkbox_kst = QCheckBox("KST (Korea Time, UTC+9)")
        self.checkbox_kst.setChecked(True)
        self.checkbox_kst.stateChanged.connect(self.on_timezone_changed)
        timezone_layout.addWidget(self.checkbox_kst)
        timezone_layout.addStretch()
        main_layout.addLayout(timezone_layout)

        # Confirmed reset time display area
        confirmed_layout = QHBoxLayout()
        self.confirmed_time_label = QLabel("Confirmed Reset Time:")
        self.confirmed_time_display = QLineEdit()
        self.confirmed_time_display.setReadOnly(True)
        self.confirmed_time_display.setPlaceholderText("No time selected.")
        self.btn_set_confirmed = QPushButton("Confirm Selected Time")
        self.btn_set_confirmed.clicked.connect(self.set_confirmed_time_from_selection)
        self.btn_clear_confirmed = QPushButton("Clear Confirmed Time")
        self.btn_clear_confirmed.clicked.connect(self.clear_confirmed_time)
        confirmed_layout.addWidget(self.confirmed_time_label)
        confirmed_layout.addWidget(self.confirmed_time_display)
        confirmed_layout.addWidget(self.btn_set_confirmed)
        confirmed_layout.addWidget(self.btn_clear_confirmed)
        main_layout.addLayout(confirmed_layout)
        
        # Text area for log output (below confirmed reset time, bottom right)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFontFamily("Courier")
        self.result_text.setVisible(True)  # Show log
        main_layout.addWidget(self.result_text)
        
        # Add left area to splitter
        main_splitter.addWidget(left_widget)
        
        # Center: Analysis results tabs (takes up left space)
        self.result_tabs = QTabWidget()
        self.result_tabs.currentChanged.connect(self.apply_confirmed_time_highlight)
        main_splitter.addWidget(self.result_tabs)
        
        # Right: Saved results tree
        saved_results_widget = QWidget()
        saved_results_layout = QVBoxLayout()
        saved_results_widget.setLayout(saved_results_layout)
        
        saved_label = QLabel("Saved Analysis Results")
        saved_label.setStyleSheet("font-weight: bold; font-size: 12pt; padding: 5px;")
        saved_results_layout.addWidget(saved_label)
        
        # Filter area
        filter_group = QGroupBox("Filter")
        filter_layout = QVBoxLayout()
        filter_group.setLayout(filter_layout)
        
        # Order filter
        order_filter_layout = QHBoxLayout()
        order_filter_layout.addWidget(QLabel("Order:"))
        self.filter_order_combo = QComboBox()
        self.filter_order_combo.setEditable(True)  # Make editable
        self.filter_order_combo.setInsertPolicy(QComboBox.NoInsert)  # Don't add new items
        self.filter_order_combo.currentTextChanged.connect(self.filter_saved_results)
        order_filter_layout.addWidget(self.filter_order_combo)
        filter_layout.addLayout(order_filter_layout)
        
        # Manufacturer filter
        manufacturer_filter_layout = QHBoxLayout()
        manufacturer_filter_layout.addWidget(QLabel("Manufacturer:"))
        self.filter_manufacturer_combo = QComboBox()
        self.filter_manufacturer_combo.setEditable(True)
        self.filter_manufacturer_combo.setInsertPolicy(QComboBox.NoInsert)
        self.filter_manufacturer_combo.currentTextChanged.connect(self.filter_saved_results)
        manufacturer_filter_layout.addWidget(self.filter_manufacturer_combo)
        filter_layout.addLayout(manufacturer_filter_layout)
        
        # Model filter
        model_filter_layout = QHBoxLayout()
        model_filter_layout.addWidget(QLabel("Model:"))
        self.filter_model_combo = QComboBox()
        self.filter_model_combo.setEditable(True)
        self.filter_model_combo.setInsertPolicy(QComboBox.NoInsert)
        self.filter_model_combo.currentTextChanged.connect(self.filter_saved_results)
        model_filter_layout.addWidget(self.filter_model_combo)
        filter_layout.addLayout(model_filter_layout)
        
        # Scenario filter
        scenario_filter_layout = QHBoxLayout()
        scenario_filter_layout.addWidget(QLabel("Scenario:"))
        self.filter_scenario_combo = QComboBox()
        self.filter_scenario_combo.setEditable(True)
        self.filter_scenario_combo.setInsertPolicy(QComboBox.NoInsert)
        self.filter_scenario_combo.currentTextChanged.connect(self.filter_saved_results)
        scenario_filter_layout.addWidget(self.filter_scenario_combo)
        filter_layout.addLayout(scenario_filter_layout)
        
        # Clear filter button
        btn_clear_filter = QPushButton("Clear Filter")
        btn_clear_filter.clicked.connect(self.clear_saved_results_filter)
        filter_layout.addWidget(btn_clear_filter)
        
        saved_results_layout.addWidget(filter_group)
        
        self.saved_results_tree = QTreeWidget()
        self.saved_results_tree.setHeaderLabels(["Saved Results"])
        self.saved_results_tree.setRootIsDecorated(True)
        self.saved_results_tree.setMinimumWidth(350)  # Increase minimum width of saved results tree
        self.saved_results_tree.itemSelectionChanged.connect(self.on_saved_result_selected)
        self.saved_results_tree.itemDoubleClicked.connect(self.on_saved_result_double_clicked)
        saved_results_layout.addWidget(self.saved_results_tree)
        
        # Store all data for filtering
        self.all_saved_results = []
        
        # Saved results management buttons
        saved_btn_layout = QHBoxLayout()
        btn_refresh_saved = QPushButton("Refresh")
        btn_refresh_saved.clicked.connect(self.load_saved_results)
        btn_delete_saved = QPushButton("Delete")
        btn_delete_saved.clicked.connect(self.delete_saved_result)
        saved_btn_layout.addWidget(btn_refresh_saved)
        saved_btn_layout.addWidget(btn_delete_saved)
        saved_results_layout.addLayout(saved_btn_layout)
        
        # Save information display
        save_info_label = QLabel("💾 Auto-saved when analysis completes\n(Save location: saved_results folder)")
        save_info_label.setStyleSheet("color: #666; font-size: 9pt; padding: 5px;")
        save_info_label.setWordWrap(True)
        saved_results_layout.addWidget(save_info_label)
        
        main_splitter.addWidget(saved_results_widget)
        
        # Main splitter size settings (left controls: 400, analysis results: 1000, right saved results: 400)
        main_splitter.setSizes([400, 1000, 400])
        
        # Initial load of saved results list
        self.load_saved_results()
        
        # Create summary results tab (added at the front)
        summary_tab = QWidget()
        summary_layout = QVBoxLayout()
        summary_tab.setLayout(summary_layout)
        
        summary_table = QTableWidget()
        summary_table.setColumnCount(5)
        summary_table.setHorizontalHeaderLabels(["Artifact", "Item", "Path", "Time", "Original Time"])
        summary_table.horizontalHeader().setStretchLastSection(True)
        summary_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        summary_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        summary_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        summary_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        summary_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        summary_table.setAlternatingRowColors(True)
        summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
        summary_table.setSortingEnabled(True)  # Enable sorting (click header to sort)
        summary_table.cellClicked.connect(self.show_summary_detail)
        summary_table.sortByColumn(3, Qt.AscendingOrder)  # Initial sort by time column
        
        summary_layout.addWidget(summary_table)
        self.summary_table = summary_table
        self.summary_tab_widget = summary_tab
        self.result_tabs.addTab(summary_tab, "✓ Summary Results")
        
        # Create deep search results tab
        deep_search_tab = QWidget()
        deep_search_layout = QVBoxLayout()
        deep_search_tab.setLayout(deep_search_layout)
        
        deep_search_table = QTableWidget()
        deep_search_table.setColumnCount(4)
        deep_search_table.setHorizontalHeaderLabels(["Search Time", "File Path", "Match Format", "Match Value"])
        deep_search_table.horizontalHeader().setStretchLastSection(False)
        deep_search_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        deep_search_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)  # User can resize
        deep_search_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        deep_search_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)  # User can resize
        # Initial column size settings
        deep_search_table.setColumnWidth(1, 400)  # Initial width of file path column
        deep_search_table.setColumnWidth(3, 200)  # Initial width of match value column
        deep_search_table.setAlternatingRowColors(True)
        deep_search_table.setEditTriggers(QTableWidget.NoEditTriggers)
        deep_search_table.setSortingEnabled(True)  # Enable sorting (click header to sort)
        deep_search_table.cellClicked.connect(self.show_deep_search_detail)
        
        deep_search_layout.addWidget(deep_search_table)
        self.deep_search_table = deep_search_table
        self.deep_search_tab_widget = deep_search_tab  # Store deep search results tab widget
        self.result_tabs.addTab(deep_search_tab, "🔍 Deep Search Results")
        
        # Create tabs for each artifact
        self.artifact_tables = {}
        self.artifact_tab_widgets = {}  # artifact_id -> tab widget mapping
        self.artifact_names = {
            "1": "bootstat",
            "21": "recovery.log",
            "22": "last_log",
            "3": "suggestions.xml",
            "4": "persistent_properties",
            "5": "appops",
            "6": "wellbing",
            "7": "internal",
            "8": "eRR.p",
            "9": "ULR_PERSISTENT_PREFS.xml"
        }
        
        for artifact_id, artifact_name in self.artifact_names.items():
            tab = QWidget()
            tab_layout = QVBoxLayout()
            tab.setLayout(tab_layout)
            
            table = QTableWidget()
            table.setColumnCount(5)  # Added checkbox column
            table.setHorizontalHeaderLabels(["", "Item", "Path", "Time", "Original Time"])
            table.horizontalHeader().setStretchLastSection(True)
            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Checkbox column
            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Item
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)  # Path
            table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Time
            table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Original Time
            table.setAlternatingRowColors(True)
            table.setEditTriggers(QTableWidget.NoEditTriggers)
            table.cellClicked.connect(lambda row, col, t=table: self.show_artifact_detail(t, row, col))
            # Set context menu for table rows
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda pos, t=table, aid=artifact_id: self.show_table_row_context_menu(pos, t, aid))
            # Connect cell changed to handle checkbox state changes (only for checkbox column)
            table.cellChanged.connect(lambda r, c, t=table, aid=artifact_id: self.on_table_cell_changed(t, r, c, aid) if c == 0 else None)
            
            tab_layout.addWidget(table)
            self.artifact_tables[artifact_id] = table
            self.artifact_tab_widgets[artifact_id] = tab
            # Initially show "(Waiting)"
            self.result_tabs.addTab(tab, f"{artifact_name} (Waiting)")
        
        # 탭 우클릭 메뉴 설정
        self.result_tabs.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_tabs.customContextMenuRequested.connect(self.show_tab_context_menu)
        
        
        # 초기 상태 설정
        self.radio_zip.setChecked(True)
        self.checkbox_all.setChecked(True)
        self.toggle_all_artifacts(Qt.Checked)
    
    def toggle_all_artifacts(self, state):
        """Toggle all artifact checkboxes based on All checkbox state"""
        checked = (state == Qt.Checked)
        # Temporarily block signals to prevent filtering from running multiple times
        for checkbox in self.artifact_checkboxes:
            checkbox.blockSignals(True)
            checkbox.setChecked(checked)
            checkbox.blockSignals(False)
        # Run filtering only once
        self.apply_artifact_filter()
    
    def on_artifact_filter_changed(self):
        """Called when artifact filter checkbox state changes"""
        # Debug: check which checkbox changed
        sender = self.sender()
        if sender:
            artifact_id = self.checkbox_to_artifact_id.get(sender, "unknown")
            checked = sender.isChecked()
            self.log(f"[Filter Changed] {artifact_id}: {'Checked' if checked else 'Unchecked'}")
        self.apply_artifact_filter()
    
    def apply_artifact_filter(self):
        """Filter artifact tabs and summary results in real-time based on checkbox state"""
        # Skip if result_tabs is not yet initialized
        if not hasattr(self, 'result_tabs') or not self.result_tabs:
                return

        # Collect checked artifact IDs
        visible_artifact_ids = set()
        
        # Show all artifacts if All checkbox is checked
        if self.checkbox_all.isChecked():
            visible_artifact_ids = set(self.artifact_names.keys())
        else:
            for checkbox, artifact_id in self.checkbox_to_artifact_id.items():
                if checkbox.isChecked():
                    visible_artifact_ids.add(artifact_id)
        
        # Debug log
        self.log(f"[Filter Applied] Visible artifacts: {visible_artifact_ids}")
        
        # Remove all artifact tabs and re-add only visible ones
        tabs_to_restore = {}  # artifact_id -> (widget, tab_text)
        
        # First find and remove all artifact tabs (remove in reverse order to avoid index issues)
        indices_to_remove = []
        for i in range(self.result_tabs.count() - 1, -1, -1):
            widget = self.result_tabs.widget(i)
            if widget in self.artifact_tab_widgets.values():
                # Artifact tab
                artifact_id = None
                for aid, w in self.artifact_tab_widgets.items():
                    if w == widget:
                        artifact_id = aid
                        break
                
                if artifact_id:
                    # Don't remove hidden artifacts
                    if artifact_id in self.hidden_artifacts:
                        continue
                    
                    tab_text = self.result_tabs.tabText(i)
                    indices_to_remove.append((i, artifact_id, widget, tab_text))
        
        # Remove tabs (in reverse order)
        for i, artifact_id, widget, tab_text in indices_to_remove:
            self.result_tabs.removeTab(i)
            # Store tabs that should be displayed for later re-addition
            if artifact_id in visible_artifact_ids:
                tabs_to_restore[artifact_id] = (widget, tab_text)
        
        # Re-add tabs to display (maintain original order)
        for artifact_id in self.artifact_names.keys():
            if artifact_id in visible_artifact_ids and artifact_id not in self.hidden_artifacts:
                widget = self.artifact_tab_widgets.get(artifact_id)
                if widget:
                    # Check if already added
                    if self.result_tabs.indexOf(widget) < 0:
                        # Add at appropriate position (between other artifact tabs)
                        insert_index = len(self.artifact_tab_widgets)
                        for i in range(self.result_tabs.count()):
                            w = self.result_tabs.widget(i)
                            if w in self.artifact_tab_widgets.values():
                                insert_index = i + 1
                                break
                        
                        # Determine tab name
                        if artifact_id in tabs_to_restore:
                            tab_text = tabs_to_restore[artifact_id][1]
                        else:
                            artifact_name = self.artifact_names.get(artifact_id, artifact_id)
                            # Check current tab name (set by update_table)
                            tab_text = f"{artifact_name} (Waiting)"
                            # Check status if artifact_data exists
                            if artifact_id in self.artifact_data:
                                data_list = self.artifact_data[artifact_id]
                                has_time = any(d.get('time') for d in data_list)
                                if has_time:
                                    tab_text = f"✓ {artifact_name}"
                                elif data_list:
                                    tab_text = f"✗ {artifact_name} (No Data)"
                        
                        self.result_tabs.insertTab(insert_index, widget, tab_text)
                        self.log(f"[Filter] Tab added: {artifact_id} ({tab_text})")
        
        # Update summary results table
        self.update_summary_table()
    
    def is_artifact_visible(self, artifact_id):
        """Check if artifact should be visible based on current filter"""
        # Show all artifacts if All checkbox is checked
        if self.checkbox_all.isChecked():
            return True
        
        # Check checkbox state
        for checkbox, aid in self.checkbox_to_artifact_id.items():
            if aid == artifact_id:
                return checkbox.isChecked()
        
        return False
    
    def select_file(self):
        """Select ZIP file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ZIP File", "", "ZIP Files (*.zip)")
        if file_path:
            # Reset previous analysis state
            self.reset_analysis_state()
            self.file_path_edit.setText(file_path)
            self.load_confirmed_time()
    
    def select_folder(self):
        """Select folder"""
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder_path:
            # Reset previous analysis state
            self.reset_analysis_state()
            self.file_path_edit.setText(folder_path)
            self.load_confirmed_time()
    
    def reset_analysis_state(self):
        """Reset analysis state (called when new file is selected)"""
        # Clean up previous analysis instance
        if hasattr(self, 'worker_thread') and self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.terminate()
            self.worker_thread.wait()
        if hasattr(self, 'deep_search_thread') and self.deep_search_thread and self.deep_search_thread.isRunning():
            self.deep_search_thread.terminate()
            self.deep_search_thread.wait()
        
        self.reset_instance = None
        
        # Initialize artifact data
        self.artifact_data = {}
        for artifact_id in self.artifact_tables.keys():
            self.clear_artifact_data(artifact_id)
        
        # Initialize result text
        if hasattr(self, 'result_text') and self.result_text:
            self.result_text.clear()
        
        # Hide progress bar
        if hasattr(self, 'progress_bar') and self.progress_bar:
            self.progress_bar.setVisible(False)
        
        # Initialize button state
        if hasattr(self, 'btn_run') and self.btn_run:
            self.btn_run.setEnabled(True)
        if hasattr(self, 'btn_deep_search') and self.btn_deep_search:
            self.btn_deep_search.setEnabled(False)
        
        # Initialize tab names
        self.reorder_tabs()

    def log(self, message):
        """Output GUI log"""
        if hasattr(self, "result_text") and self.result_text:
            self.result_text.append(message)

    def get_confirmed_time_key(self):
        """Key for saving settings"""
        path = self.file_path_edit.text().strip()
        if path:
            return os.path.abspath(path)
        return "ADB"

    def load_confirmed_time(self):
        """Load confirmed time from settings file"""
        config_path = os.path.join(os.path.dirname(__file__), "confirmed_time_settings.json")
        key = self.get_confirmed_time_key()
        try:
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {}
        except Exception:
            data = {}
        self.confirmed_time_value = data.get(key)
        if self.confirmed_time_value:
            self.confirmed_time_dt = self.parse_time_text(self.confirmed_time_value)
            self.log(f"[Confirmed Time Loaded] {self.confirmed_time_value} (parsed={self.confirmed_time_dt})")
        self.update_confirmed_time_display()
        self.apply_confirmed_time_highlight()

    def save_confirmed_time(self):
        """Save confirmed time"""
        config_path = os.path.join(os.path.dirname(__file__), "confirmed_time_settings.json")
        key = self.get_confirmed_time_key()
        try:
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {}
        except Exception:
            data = {}
        if self.confirmed_time_value:
            data[key] = self.confirmed_time_value
        else:
            data.pop(key, None)
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def update_confirmed_time_display(self):
        if self.confirmed_time_value:
            self.confirmed_time_display.setText(self.confirmed_time_value)
        else:
            self.confirmed_time_display.setText("")

    def set_confirmed_time_from_selection(self):
        """Set currently selected table cell as confirmed time"""
        table, time_col, original_col = self.get_current_result_table()
        if not table:
            self.show_message("Notice", "No selectable result table available.")
            return
        row = table.currentRow()
        if row < 0:
            self.show_message("Notice", "Please select a time to confirm.")
            return
        time_text = table.item(row, time_col).text() if table.item(row, time_col) else ""
        original_text = table.item(row, original_col).text() if table.item(row, original_col) else ""
        candidate = time_text if time_text and "없음" not in time_text else original_text
        if not candidate:
            self.show_message("Notice", "Time value is empty.")
            return
        self.confirmed_time_value = candidate
        self.confirmed_time_dt = self.parse_time_text(candidate)
        self.log(f"[Confirmed Time Set] {candidate} (parsed={self.confirmed_time_dt})")
        self.update_confirmed_time_display()
        self.save_confirmed_time()
        self.apply_confirmed_time_highlight()

    def clear_confirmed_time(self):
        self.confirmed_time_value = None
        self.confirmed_time_dt = None
        self.update_confirmed_time_display()
        self.save_confirmed_time()
        self.apply_confirmed_time_highlight()

    def get_current_result_table(self):
        """현재 탭의 테이블과 시간 컬럼 인덱스 반환"""
        current_widget = self.result_tabs.currentWidget()
        if current_widget == self.summary_tab_widget:
            return self.summary_table, 3, 4
        if current_widget == self.deep_search_tab_widget:
            return None, None, None
        for artifact_id, tab in self.artifact_tab_widgets.items():
            if tab == current_widget:
                return self.artifact_tables.get(artifact_id), 2, 3
        return None, None, None

    def normalize_time_text(self, text):
        if not text:
            return ""
        return text.replace("KST", "").replace("UTC", "").strip()

    def apply_confirmed_time_highlight(self):
        """Highlight items matching confirmed time (applied only to summary results table)"""
        if not self.confirmed_time_value:
            # Remove highlighting from summary results table only if no confirmed time
            if self.summary_table:
                self.highlight_table_rows(self.summary_table, 3, 4, None)
            return
        
        target = self.normalize_time_text(self.confirmed_time_value)
        target_dt = self.confirmed_time_dt or self.parse_time_text(self.confirmed_time_value)
        if not target_dt:
            # 파싱 실패 시에만 로그 출력
            if hasattr(self, 'result_text') and self.result_text:
                self.log(f"[Highlight] Failed to parse confirmed time: {self.confirmed_time_value}")
            if self.summary_table:
                self.highlight_table_rows(self.summary_table, 3, 4, None)
            return
        
        # Apply highlighting based on confirmed time only to summary results table
        self.highlight_table_rows(self.summary_table, 3, 4, target, target_dt)

    def clear_all_highlight(self):
        """Remove all highlighting (used when confirmed time changes)"""
        if self.summary_table:
            self.highlight_table_rows(self.summary_table, 3, 4, None)
        # Re-highlight artifact tables based on their respective times
        for artifact_id, table in self.artifact_tables.items():
            if artifact_id in self.artifact_data:
                data_list = self.artifact_data[artifact_id]
                self.highlight_artifact_table(artifact_id, table, data_list)

    def highlight_table_rows(self, table, time_col, original_col, target, target_dt=None):
        if not table:
            return
        for row in range(table.rowCount()):
            time_text = table.item(row, time_col).text() if table.item(row, time_col) else ""
            orig_text = table.item(row, original_col).text() if table.item(row, original_col) else ""
            row_item = table.item(row, 0).text().lower() if table.item(row, 0) else ""
            row_path = table.item(row, 1).text().lower() if table.item(row, 1) else ""
            is_recovery_row = ("recovery" in row_item) or ("recovery" in row_path)
            time_norm = self.normalize_time_text(time_text)
            orig_norm = self.normalize_time_text(orig_text)
            match = False
            if target_dt:
                time_dt = self.parse_time_text(time_text) or self.parse_time_text(orig_text)
                if time_dt:
                    # recovery.log 등은 UTC로 기록되는 경우가 있어 ±9시간 허용
                    diffs = [
                        abs((time_dt - target_dt).total_seconds()),
                        abs((time_dt + timedelta(hours=9) - target_dt).total_seconds()),
                        abs((time_dt - timedelta(hours=9) - target_dt).total_seconds()),
                    ]
                    match = min(diffs) <= 60
                    if is_recovery_row:
                        self.log(f"[Highlight Debug] recovery time_dt={time_dt} target_dt={target_dt} diffs={diffs} time='{time_text}' orig='{orig_text}'")
                else:
                    if is_recovery_row:
                        self.log(f"[Highlight Debug] recovery parsing failed: time='{time_text}' orig='{orig_text}' target='{self.confirmed_time_value}'")
            if not match and target:
                match = (target in time_norm) or (target in orig_norm) or (time_norm in target) or (orig_norm in target)
            for col in range(table.columnCount()):
                item = table.item(row, col)
                if not item:
                    continue
                if match:
                    item.setBackground(Qt.yellow)
                else:
                    item.setBackground(Qt.white)

    def parse_time_text(self, text):
        if not text:
            return None
        raw = text.replace("KST", "").replace("UTC", "").strip()

        # Extract recovery.log original format (Fri Dec  6 05:37:34 2024)
        rec_match = re.search(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\b", raw)
        if rec_match:
            rec_str = " ".join(rec_match.group(0).split())
            try:
                return datetime.strptime(rec_str, "%a %b %d %H:%M:%S %Y")
            except Exception:
                pass

        # Extract date/time pattern from string first
        dt_match = re.search(r"\d{4}[-/\.]\d{2}[-/\.]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+\d{4}|\+\d{2}:\d{2})?", raw)
        if dt_match:
            raw = dt_match.group(0)

        # Handle timezone-included pattern
        if re.search(r"\+\d{4}$", raw):
            try:
                return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S%z").replace(tzinfo=None)
            except Exception:
                pass
        if re.search(r"\+\d{2}:\d{2}$", raw):
            try:
                return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S%z").replace(tzinfo=None)
            except Exception:
                pass

        # recovery.log 원문 포맷 (Fri Dec  6 05:37:34 2024)
        try:
            alt = datetime.strptime(raw, "%a %b %d %H:%M:%S %Y")
            return alt
        except Exception:
            pass

        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S", "%Y.%m.%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt)
            except Exception:
                continue
        return None
    
    def get_selected_source(self):
        """Return selected search target"""
        if self.radio_zip.isChecked():
            return "1"
        elif self.radio_adb.isChecked():
            return "2"
        elif self.radio_folder.isChecked():
            return "3"
        return None
    
    def get_selected_artifacts(self):
        """Return selected artifact list"""
        if self.checkbox_all.isChecked():
            return "0"
        
        selected = []
        artifact_map = {
            self.checkbox_bootstat: "1",
            self.checkbox_recovery_log: "21",
            self.checkbox_last_log: "22",
            self.checkbox_suggestions: "3",
            self.checkbox_persistent: "4",
            self.checkbox_appops: "5",
            self.checkbox_wellbing: "6",
            self.checkbox_internal: "7",
            self.checkbox_err: "8",
            self.checkbox_ulr: "9"
        }
        
        for checkbox, value in artifact_map.items():
            if checkbox.isChecked():
                selected.append(value)
        
        return selected if selected else ["0"]
    
    def on_timezone_changed(self, state):
        """Update tables when timezone changes"""
        self.use_kst = (state == Qt.Checked)
        self.update_all_tables()
    
    def update_all_tables(self):
        """Update all tables according to timezone"""
        for artifact_id, table in self.artifact_tables.items():
            if artifact_id in self.artifact_data:
                self.update_table(artifact_id, self.artifact_data[artifact_id])
        
        # 필터링 적용
        self.apply_artifact_filter()
        
        # Update summary results tab as well
        self.update_summary_table()
    
    def update_table(self, artifact_id, data_list):
        """Update table for specific artifact"""
        table = self.artifact_tables.get(artifact_id)
        if not table:
            return
        
        table.setRowCount(0)
        
        # Check if data exists (if there are items with time information)
        has_time_data = False
        for data in data_list:
            if data.get('time'):
                has_time_data = True
                break
        
        # Update tab name (including status info) - only if not hidden and visible by filter
        if artifact_id not in self.hidden_artifacts and self.is_artifact_visible(artifact_id):
            base_name = self.artifact_names.get(artifact_id, artifact_id)
            if has_time_data:
                tab_name = f"✓ {base_name}"
            elif data_list:
                tab_name = f"✗ {base_name} (No Data)"
            else:
                # Detailed status information while waiting
                if not self.analysis_running:
                    # Before analysis
                    status = "Before Analysis"
                elif artifact_id not in self.selected_artifacts and "0" not in self.selected_artifacts:
                    # Not selected
                    status = "Not Selected"
                elif self.analysis_running:
                    # Analyzing
                    status = "Analyzing"
                else:
                    # Analysis completed but no data
                    status = "No Data"
                tab_name = f"{base_name} ({status})"
            
            # Find tab index
            for i in range(self.result_tabs.count()):
                widget = self.result_tabs.widget(i)
                if widget == self.artifact_tab_widgets.get(artifact_id):
                    self.result_tabs.setTabText(i, tab_name)
                    break
        
        # Display status information in table even when there is no data
        if not data_list:
            table.insertRow(0)
            # Checkbox column (empty for status row)
            checkbox_item = QTableWidgetItem("")
            checkbox_item.setFlags(Qt.NoItemFlags)
            table.setItem(0, 0, checkbox_item)
            
            item_name = QTableWidgetItem("Status")
            table.setItem(0, 1, item_name)
            
            item_path = QTableWidgetItem("")
            table.setItem(0, 2, item_path)
            
            # Status message
            if not self.analysis_running:
                status_msg = "Analysis has not been run yet."
            elif artifact_id not in self.selected_artifacts and "0" not in self.selected_artifacts:
                status_msg = "This artifact was not selected."
            elif self.analysis_running:
                status_msg = "Analysis is in progress. Please wait..."
            else:
                status_msg = "Analysis completed but no data found."
            
            item_time = QTableWidgetItem(status_msg)
            table.setItem(0, 3, item_time)
            
            item_original = QTableWidgetItem("")
            table.setItem(0, 4, item_original)
        
        # Filter out hidden items
        visible_data_list = []
        for data in data_list:
            item_key = self._get_item_key(data)
            hidden_items = self.hidden_items.get(artifact_id, set())
            if item_key not in hidden_items:
                visible_data_list.append(data)
        
        for row, data in enumerate(visible_data_list):
            table.insertRow(row)
            
            # Create item key for this row
            item_key = self._get_item_key(data)
            hidden_items = self.hidden_items.get(artifact_id, set())
            is_hidden = item_key in hidden_items
            
            # Checkbox column
            checkbox_item = QTableWidgetItem()
            checkbox_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox_item.setCheckState(Qt.Unchecked if is_hidden else Qt.Checked)
            checkbox_item.setData(Qt.UserRole, item_key)  # Store item_key for reference
            table.setItem(row, 0, checkbox_item)
            
            # 항목
            item_name = QTableWidgetItem(data.get('name', ''))
            table.setItem(row, 1, item_name)
            
            # 경로
            item_path = QTableWidgetItem(data.get('path', ''))
            table.setItem(row, 2, item_path)
            
            # Time (converted according to timezone)
            time_value = data.get('time')
            is_kst = data.get('is_kst', False)  # Check if already KST
            
            if time_value:
                if isinstance(time_value, datetime):
                    if is_kst:
                        # If already KST, don't convert
                        if self.use_kst:
                            time_str = time_value.strftime('%Y-%m-%d %H:%M:%S KST')
                        else:
                            # Subtract 9 hours to display as UTC
                            display_time = time_value - timedelta(hours=9)
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                    else:
                        # UTC인 경우
                        if self.use_kst:
                            display_time = time_value + timedelta(hours=9)
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S KST')
                        else:
                            display_time = time_value
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                else:
                    time_str = str(time_value)
            else:
                time_str = data.get('message', 'No time information')
            
            item_time = QTableWidgetItem(time_str)
            table.setItem(row, 3, item_time)
            
            # Display original time
            original_time = data.get('original_time')
            if original_time:
                if isinstance(original_time, datetime):
                    original_time_str = original_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    original_time_str = str(original_time)
            else:
                original_time_str = time_str if time_value else ''
            
            item_original = QTableWidgetItem(original_time_str)
            table.setItem(row, 4, item_original)
        
        table.resizeColumnsToContents()
        # Each artifact table is highlighted based on that artifact's time data
        self.highlight_artifact_table(artifact_id, table, data_list)
    
    def highlight_artifact_table(self, artifact_id, table, data_list):
        """Highlight based on time extracted from each artifact table"""
        if not table or not data_list:
            return
        
        # Collect all times extracted from that artifact
        extracted_times = []
        for data in data_list:
            time_value = data.get('time')
            if time_value and isinstance(time_value, datetime):
                extracted_times.append(time_value)
        
        if not extracted_times:
            # Don't highlight if no time
            return
        
        # Compare with each row's time and highlight
        for row in range(table.rowCount()):
            time_item = table.item(row, 2)
            orig_item = table.item(row, 3)
            
            if not time_item:
                continue
            
            time_text = time_item.text()
            orig_text = orig_item.text() if orig_item else ""
            
            # Parse current row's time
            row_time_dt = self.parse_time_text(time_text) or self.parse_time_text(orig_text)
            
            # For persistent_properties, original time may be in special format, so compare directly
            if not row_time_dt and artifact_id == "4" and orig_text:
                # Try to extract epoch value from original time
                epoch_match = re.search(r'(\d{10})', orig_text)
                if epoch_match:
                    try:
                        epoch_value = int(epoch_match.group(1))
                        if epoch_value > 253402300799:
                            epoch_value /= 1000
                        row_time_dt = datetime.utcfromtimestamp(epoch_value)
                    except (ValueError, OverflowError):
                        pass
            
            if not row_time_dt:
                continue
            
            # Compare with extracted times (±1 minute allowed)
            match = False
            for extracted_dt in extracted_times:
                # Allow ±9 hours considering UTC/KST difference
                diffs = [
                    abs((row_time_dt - extracted_dt).total_seconds()),
                    abs((row_time_dt + timedelta(hours=9) - extracted_dt).total_seconds()),
                    abs((row_time_dt - timedelta(hours=9) - extracted_dt).total_seconds()),
                ]
                if min(diffs) <= 60:  # Difference within 1 minute
                    match = True
                    break
            
            # 하이라이팅 적용
            for col in range(table.columnCount()):
                item = table.item(row, col)
                if item:
                    if match:
                        item.setBackground(Qt.yellow)
                    else:
                        item.setBackground(Qt.white)
    
    def update_summary_table(self):
        """Update summary results tab - display all artifacts' time information sorted by time"""
        if not self.summary_table:
            return
        
        self.summary_table.setRowCount(0)
        
        # Collect data with time information from all artifacts
        all_time_data = []
        
        for artifact_id, data_list in self.artifact_data.items():
            # Exclude hidden artifacts from summary results
            if artifact_id in self.hidden_artifacts:
                continue
            
            # Filtering: show only artifacts selected by checkbox
            if not self.is_artifact_visible(artifact_id):
                continue
                
            artifact_name = self.artifact_names.get(artifact_id, artifact_id)
            
            for data in data_list:
                # Filter out hidden items
                item_key = self._get_item_key(data)
                hidden_items = self.hidden_items.get(artifact_id, set())
                if item_key in hidden_items:
                    continue
                
                time_value = data.get('time')
                if time_value and isinstance(time_value, datetime):
                    # Timezone conversion
                    is_kst = data.get('is_kst', False)
                    
                    if is_kst:
                        # If already KST
                        if self.use_kst:
                            display_time = time_value
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S KST')
                        else:
                            display_time = time_value - timedelta(hours=9)
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                    else:
                        # If UTC
                        if self.use_kst:
                            display_time = time_value + timedelta(hours=9)
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S KST')
                        else:
                            display_time = time_value
                            time_str = display_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                    
                    # Original time data
                    original_time = data.get('original_time')
                    if original_time:
                        if isinstance(original_time, datetime):
                            original_time_str = original_time.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            original_time_str = str(original_time)
                    else:
                        original_time_str = time_str
                    
                    all_time_data.append({
                        'time': display_time,
                        'artifact_name': artifact_name,
                        'name': data.get('name', ''),
                        'path': data.get('path', ''),
                        'time_str': time_str,
                        'original_time_str': original_time_str
                    })
        
        # Sort by time
        all_time_data.sort(key=lambda x: x['time'])
        
        # Add to table
        for row, data in enumerate(all_time_data):
            self.summary_table.insertRow(row)
            
            # Artifact name
            item_artifact = QTableWidgetItem(data['artifact_name'])
            self.summary_table.setItem(row, 0, item_artifact)
            
            # Item name
            item_name = QTableWidgetItem(data['name'])
            self.summary_table.setItem(row, 1, item_name)
            
            # 경로
            item_path = QTableWidgetItem(data['path'])
            self.summary_table.setItem(row, 2, item_path)
            
            # 시간
            item_time = QTableWidgetItem(data['time_str'])
            # Store datetime object for sorting (convert to number)
            item_time.setData(Qt.UserRole, data['time'].timestamp())
            self.summary_table.setItem(row, 3, item_time)
            
            # Original time
            item_original = QTableWidgetItem(data['original_time_str'])
            self.summary_table.setItem(row, 4, item_original)
        
        self.summary_table.resizeColumnsToContents()
        self.apply_confirmed_time_highlight()
        
        # Sort by time column (ascending order)
        if all_time_data:
            self.summary_table.sortItems(3, Qt.AscendingOrder)
    
    def reorder_tabs(self):
        """Reorder tabs: display tabs with data first"""
        # Check status of each artifact
        tab_states = []  # (artifact_id, has_data, has_time, base_name)
        
        for artifact_id, base_name in self.artifact_names.items():
            has_data = artifact_id in self.artifact_data and len(self.artifact_data[artifact_id]) > 0
            has_time = False
            if has_data:
                for data in self.artifact_data[artifact_id]:
                    if data.get('time'):
                        has_time = True
                        break
            
            tab_states.append((artifact_id, has_data, has_time, base_name))
        
        # Sort: tabs with time data > tabs with data but no time > tabs with no data
        tab_states.sort(key=lambda x: (not x[2], not x[1]))
        
        # Store currently selected tab index
        current_index = self.result_tabs.currentIndex()
        current_widget = self.result_tabs.currentWidget() if current_index >= 0 else None
        
        # Store summary results tab and deep search results tab widgets
        summary_widget = None
        deep_search_widget = None
        summary_index = -1
        deep_search_index = -1
        
        # Find tab widgets
        for i in range(self.result_tabs.count()):
            tab_text = self.result_tabs.tabText(i)
            if "Summary Results" in tab_text or tab_text.startswith("✓ Summary"):
                summary_widget = self.result_tabs.widget(i)
                summary_index = i if current_index == i else -1
            elif "Deep Search Results" in tab_text or "🔍" in tab_text:
                deep_search_widget = self.result_tabs.widget(i)
                deep_search_index = i if current_index == i else -1
        
        # 모든 탭 제거 (위젯은 유지)
        while self.result_tabs.count() > 0:
            self.result_tabs.removeTab(0)
        
        # Summary results tab added first
        new_current_index = -1
        if summary_widget:
            self.result_tabs.addTab(summary_widget, "✓ Summary Results")
            if summary_index >= 0:
                new_current_index = 0
        
        # Deep search results tab added (second)
        if deep_search_widget:
            self.result_tabs.addTab(deep_search_widget, "🔍 Deep Search Results")
            if deep_search_index >= 0:
                new_current_index = 1
        
        # 정렬된 순서대로 탭 다시 추가
        start_idx = 1
        if summary_widget:
            start_idx += 1
        if deep_search_widget:
            start_idx += 1
        for idx, (artifact_id, has_data, has_time, base_name) in enumerate(tab_states):
            tab_widget = self.artifact_tab_widgets[artifact_id]
            
            # Determine tab name
            if has_time:
                tab_name = f"✓ {base_name}"
            elif has_data:
                tab_name = f"✗ {base_name} (No Data)"
            else:
                # Detailed status information while waiting
                if artifact_id not in self.selected_artifacts and "0" not in self.selected_artifacts:
                    status = "Not Selected"
                else:
                    status = "No Data"
                tab_name = f"{base_name} ({status})"
            
            self.result_tabs.addTab(tab_widget, tab_name)
            
            # 이전에 선택된 탭이면 인덱스 저장
            if current_widget and tab_widget == current_widget:
                new_current_index = start_idx + idx
        
        # 이전 선택 복원
        if new_current_index >= 0:
            self.result_tabs.setCurrentIndex(new_current_index)
        elif summary_index == 0:
            self.result_tabs.setCurrentIndex(0)
    
    def add_artifact_data(self, artifact_id, name, path, time_value=None, message=None, is_kst=False, original_time=None):
        """아티팩트 데이터 추가
        Args:
            artifact_id: 아티팩트 ID
            name: 항목 이름
            path: 파일 경로
            time_value: 시간 값 (datetime 객체 또는 None)
            message: 메시지 (시간이 없을 때 표시)
            is_kst: 이미 KST 시간인지 여부 (True면 UTC 변환 안 함)
            original_time: 원본 시간 데이터 (정규화 전)
        """
        if artifact_id not in self.artifact_data:
            self.artifact_data[artifact_id] = []
        
        self.artifact_data[artifact_id].append({
            'name': name,
            'path': path,
            'time': time_value,
            'message': message,
            'is_kst': is_kst,  # 이미 KST인 경우 플래그
            'original_time': original_time  # 원본 시간 데이터
        })
        
        # 표 업데이트
        self.update_table(artifact_id, self.artifact_data[artifact_id])
        
        # 종합 결과 탭 업데이트
        self.update_summary_table()
    
    def clear_artifact_data(self, artifact_id):
        """아티팩트 데이터 초기화"""
        if artifact_id in self.artifact_data:
            self.artifact_data[artifact_id] = []
        table = self.artifact_tables.get(artifact_id)
        if table:
            table.setRowCount(0)
    
    def run_analysis(self):
        """분석 실행"""
        # 입력 검증
        source = self.get_selected_source()
        if not source:
            self.show_message("경고", "검색 대상을 선택하세요.")
            return
        
        if source in ["1", "3"]:
            file_path = self.file_path_edit.text()
            if not file_path:
                self.show_message("경고", "파일 또는 폴더를 선택하세요.")
                return
        
        artifacts = self.get_selected_artifacts()
        if not artifacts:
            self.show_message("경고", "최소 하나의 아티팩트를 선택하세요.")
            return
        
        # 선택된 아티팩트 저장
        self.selected_artifacts = artifacts if isinstance(artifacts, list) else [artifacts]
        self.analysis_running = True
        
        # 이전 분석 인스턴스 정리
        if hasattr(self, 'worker_thread') and self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.terminate()
            self.worker_thread.wait()
        if hasattr(self, 'deep_search_thread') and self.deep_search_thread and self.deep_search_thread.isRunning():
            self.deep_search_thread.terminate()
            self.deep_search_thread.wait()
        
        self.reset_instance = None
        
        # 데이터 초기화
        self.artifact_data = {}
        for artifact_id in self.artifact_tables.keys():
            self.clear_artifact_data(artifact_id)
            # Update all tabs to "Analyzing" or "Not Selected" status
            self.update_table(artifact_id, [])
        
        # Initialize summary results tab
        if self.summary_table:
            self.summary_table.setRowCount(0)
        
        self.result_text.clear()
        self.result_text.append("=" * 60)
        self.result_text.append("Factory Reset Artifact Analysis 시작")
        self.result_text.append("=" * 60 + "\n")
        
        # 진행 표시줄 표시
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 무한 진행
        self.btn_run.setEnabled(False)
        
        # ResetClass 인스턴스 생성 및 설정
        self.reset_instance = ResetClassGUI(source, artifacts, self.file_path_edit.text(), 
                                            self.result_text, self)
        
        # 백그라운드 스레드에서 실행
        self.worker_thread = WorkerThread(self.reset_instance)
        self.worker_thread.output.connect(self.result_text.append)
        self.worker_thread.finished.connect(self.analysis_finished)
        self.worker_thread.start()
    
    def analysis_finished(self):
        """분석 완료 처리"""
        self.analysis_running = False
        self.progress_bar.setVisible(False)
        self.btn_run.setEnabled(True)
        self.btn_deep_search.setEnabled(True)  # Enable deep search button
        self.result_text.append("\n" + "=" * 60)
        self.result_text.append("분석 완료")
        self.result_text.append("=" * 60)
        
        # 모든 탭 상태 업데이트 (분석 완료 후 상태 반영)
        for artifact_id in self.artifact_tables.keys():
            data_list = self.artifact_data.get(artifact_id, [])
            self.update_table(artifact_id, data_list)
        
        # 탭 순서 재정렬 (데이터가 있는 탭을 먼저)
        self.reorder_tabs()
        
        # 분석 결과 자동 저장
        self.save_analysis_result()
    
    def run_deep_search(self):
        """Execute deep search - search files using extracted times"""
        if not self.reset_instance:
            self.show_message("경고", "먼저 분석을 실행하세요.")
            return
        
        # 추출된 시간 정보 수집
        search_times = []
        for artifact_id, data_list in self.artifact_data.items():
            for data in data_list:
                time_value = data.get('time')
                if time_value and isinstance(time_value, datetime):
                    is_kst = data.get('is_kst', False)
                    # UTC로 변환 (검색용)
                    if is_kst:
                        utc_time = time_value - timedelta(hours=9)
                    else:
                        utc_time = time_value
                    search_times.append({
                        'time': utc_time,
                        'original_time': data.get('original_time'),
                        'artifact_id': artifact_id,
                        'name': data.get('name', ''),
                        'path': data.get('path', '')
                    })
        
        if not search_times:
            self.show_message("정보", "검색할 시간 정보가 없습니다.")
            return
        
        # Initialize deep search results tab
        if self.deep_search_table:
            self.deep_search_table.setRowCount(0)
        
        # 진행 표시줄 표시
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 무한 진행 (파일 수를 알 때까지)
        self.progress_bar.setFormat("Preparing Deep Search...")
        self.btn_deep_search.setEnabled(False)
        
        # 백그라운드에서 검색 실행 (시간 오차 허용 범위: 300초 = 5분)
        time_tolerance = 300  # 5분 오차 허용
        self.deep_search_thread = DeepSearchThread(self.reset_instance, search_times, self, time_tolerance)
        self.deep_search_thread.result_found.connect(self.add_deep_search_result)
        self.deep_search_thread.progress_updated.connect(self.update_deep_search_progress)
        self.deep_search_thread.finished.connect(self.deep_search_finished)
        self.deep_search_thread.start()
    
    def add_deep_search_result(self, search_time_str, file_path, match_format, match_value):
        """Add deep search result"""
        if not self.deep_search_table:
            return
        
        row = self.deep_search_table.rowCount()
        self.deep_search_table.insertRow(row)
        
        self.deep_search_table.setItem(row, 0, QTableWidgetItem(search_time_str))
        self.deep_search_table.setItem(row, 1, QTableWidgetItem(file_path))
        self.deep_search_table.setItem(row, 2, QTableWidgetItem(match_format))
        match_item = QTableWidgetItem(str(match_value))
        # "시간 없음" 표시가 붙은 경우 원본 매칭값을 저장
        raw_match_value = str(match_value).replace(" (시간 없음)", "")
        if str(match_format).startswith("hex_") or str(match_format) == "file_mtime":
            raw_match_value = ""
        match_item.setData(Qt.UserRole, raw_match_value)
        self.deep_search_table.setItem(row, 3, match_item)
        
        self.deep_search_table.resizeColumnsToContents()

    def show_deep_search_detail(self, row, column):
        """View deep search result details"""
        if not self.deep_search_table:
            return

        def get_text(col):
            item = self.deep_search_table.item(row, col)
            return item.text() if item else ""

        search_time = get_text(0)
        file_path = get_text(1)
        match_format = get_text(2)
        match_item = self.deep_search_table.item(row, 3)
        match_value = get_text(3)
        raw_match_value = match_item.data(Qt.UserRole) if match_item else match_value

        if not any([search_time, file_path, match_format, match_value]):
            return

        raw_info, raw_error = self.get_deep_search_raw_data(file_path, raw_match_value)

        dialog = QDialog(self)
        dialog.setWindowTitle("Deep Search Details")
        dialog_layout = QVBoxLayout()
        dialog.setLayout(dialog_layout)

        header = QTextEdit()
        header.setReadOnly(True)
        header.setPlainText(
            f"검색 시간: {search_time}\n"
            f"파일 경로: {file_path}\n"
            f"매칭 형식: {match_format}\n"
            f"매칭 값: {match_value}"
        )
        header.setFontFamily("Courier")
        header.setFixedHeight(90)
        dialog_layout.addWidget(header)

        tabs = QTabWidget()
        dialog_layout.addWidget(tabs)

        raw_text = QTextEdit()
        raw_text.setReadOnly(True)
        raw_text.setFontFamily("Courier")

        hex_text = QTextEdit()
        hex_text.setReadOnly(True)
        hex_text.setFontFamily("Courier")

        if raw_error:
            raw_text.setPlainText(f"원문 데이터: {raw_error}")
            hex_text.setPlainText(f"HEX 데이터: {raw_error}")
        else:
            raw_text.setPlainText(
                f"원문 데이터 (라인 {raw_info['line_no']}):\n"
                f"{raw_info['snippet']}"
            )
            hex_view = self.format_hex_view(
                raw_info['raw_bytes'],
                raw_info.get('byte_offset'),
                raw_info.get('encoding'),
                show_full=True
            )
            hex_text.setPlainText(hex_view)

        tabs.addTab(raw_text, "원문")
        tabs.addTab(hex_text, "HEX/디코딩")

        dialog.resize(800, 600)
        dialog.exec_()

    def show_summary_detail(self, row, column):
        """View summary results details (original/HEX)"""
        if not self.summary_table:
            return

        def get_text(col):
            item = self.summary_table.item(row, col)
            return item.text() if item else ""

        artifact_name = get_text(0)
        item_name = get_text(1)
        file_path = get_text(2)
        time_value = get_text(3)
        original_time = get_text(4)

        match_hint = original_time or time_value
        header_text = (
            f"아티팩트: {artifact_name}\n"
            f"항목: {item_name}\n"
            f"파일 경로: {file_path}\n"
            f"시간: {time_value}\n"
            f"원본 시간: {original_time}"
        )
        self.show_raw_hex_dialog("Summary Results Details", header_text, file_path, match_hint)

    def show_tab_context_menu(self, position):
        """탭 우클릭 메뉴 표시"""
        tab_index = self.result_tabs.tabBar().tabAt(position)
        if tab_index < 0:
            return
        
        # Check if artifact tab (excluding deep search results tab)
        tab_widget = self.result_tabs.widget(tab_index)
        artifact_id = None
        for aid, widget in self.artifact_tab_widgets.items():
            if widget == tab_widget:
                artifact_id = aid
                break
        
        if artifact_id is None:
            return
        
        artifact_name = self.artifact_names.get(artifact_id, artifact_id)
        is_hidden = artifact_id in self.hidden_artifacts
        
        menu = QMenu(self)
        if is_hidden:
            show_action = menu.addAction("표시하기")
            show_action.triggered.connect(lambda: self.show_artifact(artifact_id))
        else:
            hide_action = menu.addAction("숨기기")
            hide_action.triggered.connect(lambda: self.hide_artifact(artifact_id))
        
        menu.exec_(self.result_tabs.tabBar().mapToGlobal(position))
    
    def hide_artifact(self, artifact_id):
        """아티팩트 숨기기"""
        if artifact_id not in self.hidden_artifacts:
            self.hidden_artifacts.add(artifact_id)
            # 탭 숨기기
            tab_widget = self.artifact_tab_widgets.get(artifact_id)
            if tab_widget:
                tab_index = self.result_tabs.indexOf(tab_widget)
                if tab_index >= 0:
                    self.result_tabs.removeTab(tab_index)
            # Update summary results
            self.update_summary_table()
    
    def show_artifact(self, artifact_id):
        """아티팩트 표시하기"""
        if artifact_id in self.hidden_artifacts:
            self.hidden_artifacts.remove(artifact_id)
            # 탭 다시 추가
            tab_widget = self.artifact_tab_widgets.get(artifact_id)
            if tab_widget:
                artifact_name = self.artifact_names.get(artifact_id, artifact_id)
                # 이미 탭이 있는지 확인
                if self.result_tabs.indexOf(tab_widget) < 0:
                    # 적절한 위치에 탭 추가 (다른 아티팩트 탭들 사이에)
                    insert_index = len(self.artifact_tab_widgets)
                    for i in range(self.result_tabs.count()):
                        widget = self.result_tabs.widget(i)
                        if widget in self.artifact_tab_widgets.values():
                            insert_index = i + 1
                        break
                    self.result_tabs.insertTab(insert_index, tab_widget, artifact_name)
            # Update summary results
            self.update_summary_table()

    def _get_item_key(self, data):
        """Generate unique key for an item"""
        path = data.get('path', '')
        name = data.get('name', '')
        return f"{path}|{name}"
    
    def on_item_visibility_changed(self, artifact_id, item_key, state):
        """Handle checkbox state change for item visibility"""
        if artifact_id not in self.hidden_items:
            self.hidden_items[artifact_id] = set()
        
        if state == Qt.Unchecked:
            # Hide item
            self.hidden_items[artifact_id].add(item_key)
        else:
            # Show item
            self.hidden_items[artifact_id].discard(item_key)
        
        # Refresh table to apply changes
        if artifact_id in self.artifact_data:
            self.update_table(artifact_id, self.artifact_data[artifact_id])
        # Update summary table
        self.update_summary_table()
    
    def show_table_row_context_menu(self, position, table, artifact_id):
        """Show context menu for table row"""
        row = table.rowAt(position.y())
        if row < 0:
            return
        
        item_key_item = table.item(row, 0)  # Checkbox item
        if not item_key_item:
            return
        
        item_key = item_key_item.data(Qt.UserRole)
        if not item_key:
            return
        
        hidden_items = self.hidden_items.get(artifact_id, set())
        is_hidden = item_key in hidden_items
        
        menu = QMenu(self)
        if is_hidden:
            show_action = menu.addAction("Show Item")
            show_action.triggered.connect(lambda: self.toggle_item_visibility(artifact_id, item_key, True))
        else:
            hide_action = menu.addAction("Hide Item")
            hide_action.triggered.connect(lambda: self.toggle_item_visibility(artifact_id, item_key, False))
        
        menu.exec_(table.viewport().mapToGlobal(position))
    
    def toggle_item_visibility(self, artifact_id, item_key, show):
        """Toggle item visibility"""
        if artifact_id not in self.hidden_items:
            self.hidden_items[artifact_id] = set()
        
        if show:
            self.hidden_items[artifact_id].discard(item_key)
        else:
            self.hidden_items[artifact_id].add(item_key)
        
        # Refresh table
        if artifact_id in self.artifact_data:
            self.update_table(artifact_id, self.artifact_data[artifact_id])
        # Update summary table
        self.update_summary_table()
    
    def show_item_visibility_settings(self):
        """Show item visibility settings dialog"""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QLabel, QMessageBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Item Visibility Settings")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Instructions
        info_label = QLabel("Select items to hide/show. Hidden items will not appear in tables.")
        layout.addWidget(info_label)
        
        # List of hidden items by artifact
        list_widget = QListWidget()
        layout.addWidget(list_widget)
        
        # Populate list
        for artifact_id, hidden_set in self.hidden_items.items():
            if hidden_set:
                artifact_name = self.artifact_names.get(artifact_id, artifact_id)
                for item_key in hidden_set:
                    path, name = item_key.split('|', 1) if '|' in item_key else ('', item_key)
                    list_widget.addItem(f"[{artifact_name}] {name} - {path}")
                    list_widget.item(list_widget.count() - 1).setData(Qt.UserRole, (artifact_id, item_key))
        
        if list_widget.count() == 0:
            list_widget.addItem("No hidden items")
            list_widget.item(0).setFlags(Qt.NoItemFlags)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        btn_show_selected = QPushButton("Show Selected")
        btn_show_selected.clicked.connect(lambda: self.show_selected_items(list_widget))
        button_layout.addWidget(btn_show_selected)
        
        btn_show_all = QPushButton("Show All")
        btn_show_all.clicked.connect(lambda: self.show_all_hidden_items(list_widget))
        button_layout.addWidget(btn_show_all)
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        button_layout.addWidget(btn_close)
        
        layout.addLayout(button_layout)
        
        dialog.exec_()
    
    def show_selected_items(self, list_widget):
        """Show selected hidden items"""
        from PyQt5.QtWidgets import QMessageBox
        
        selected_items = list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "Information", "Please select items to show.")
            return
        
        for item in selected_items:
            data = item.data(Qt.UserRole)
            if data:
                artifact_id, item_key = data
                if artifact_id not in self.hidden_items:
                    self.hidden_items[artifact_id] = set()
                self.hidden_items[artifact_id].discard(item_key)
                list_widget.takeItem(list_widget.row(item))
        
        # Refresh tables
        for artifact_id in self.artifact_data:
            self.update_table(artifact_id, self.artifact_data[artifact_id])
        self.update_summary_table()
        
        if list_widget.count() == 0:
            list_widget.addItem("No hidden items")
            list_widget.item(0).setFlags(Qt.NoItemFlags)
    
    def show_all_hidden_items(self, list_widget):
        """Show all hidden items"""
        from PyQt5.QtWidgets import QMessageBox
        
        reply = QMessageBox.question(self, "Confirm", "Show all hidden items?",
                                    QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.hidden_items.clear()
            list_widget.clear()
            list_widget.addItem("No hidden items")
            list_widget.item(0).setFlags(Qt.NoItemFlags)
            
            # Refresh tables
            for artifact_id in self.artifact_data:
                self.update_table(artifact_id, self.artifact_data[artifact_id])
            self.update_summary_table()
    
    def on_table_cell_changed(self, table, row, col, artifact_id):
        """Handle checkbox state change in table"""
        if col != 0:  # Only handle checkbox column
            return
        
        checkbox_item = table.item(row, 0)
        if not checkbox_item:
            return
        
        item_key = checkbox_item.data(Qt.UserRole)
        if not item_key:
            return
        
        state = checkbox_item.checkState()
        self.on_item_visibility_changed(artifact_id, item_key, state)
    
    def show_artifact_detail(self, table, row, column):
        """아티팩트 결과 상세 보기 (원문/HEX)"""
        if not table:
            return
        
        # Skip if clicking on checkbox column
        if column == 0:
            return

        def get_text(col):
            item = table.item(row, col)
            return item.text() if item else ""

        item_name = get_text(1)  # Adjusted for checkbox column
        file_path = get_text(2)  # Adjusted for checkbox column
        time_value = get_text(3)  # Adjusted for checkbox column
        original_time = get_text(4)  # Adjusted for checkbox column

        match_hint = original_time or time_value
        header_text = (
            f"항목: {item_name}\n"
            f"파일 경로: {file_path}\n"
            f"시간: {time_value}\n"
            f"원본 시간: {original_time}"
        )
        abx_text = None
        if item_name and "appops" in item_name.lower() and self.reset_instance:
            abx_text = getattr(self.reset_instance, "last_abx_output", None)
        self.show_raw_hex_dialog("아티팩트 상세", header_text, file_path, match_hint, abx_text=abx_text)

    def show_raw_hex_dialog(self, title, header_text, file_path, match_hint, abx_text=None):
        """원문/HEX 뷰 다이얼로그 표시"""
        if not file_path:
            self.show_message("상세 보기", "파일 경로가 없습니다.")
            return

        text, raw_bytes, error = self.get_file_content_for_detail(file_path)

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog_layout = QVBoxLayout()
        dialog.setLayout(dialog_layout)

        header = QTextEdit()
        header.setReadOnly(True)
        header.setPlainText(header_text)
        header.setFontFamily("Courier")
        header.setFixedHeight(110)
        dialog_layout.addWidget(header)

        tabs = QTabWidget()

        # 검색 바
        search_layout = QHBoxLayout()
        search_label = QLabel("찾기:")
        search_input = QLineEdit()
        search_input.setPlaceholderText("찾을 문자열 입력")
        btn_find_next = QPushButton("다음")
        btn_find_prev = QPushButton("이전")
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_input)
        search_layout.addWidget(btn_find_next)
        search_layout.addWidget(btn_find_prev)
        dialog_layout.addLayout(search_layout)

        dialog_layout.addWidget(tabs)

        raw_text = QTextEdit()
        raw_text.setReadOnly(True)
        raw_text.setFontFamily("Courier")

        hex_text = QTextEdit()
        hex_text.setReadOnly(True)
        hex_text.setFontFamily("Courier")

        if error:
            raw_text.setPlainText(f"원문 데이터: {error}")
            hex_text.setPlainText(f"HEX 데이터: {error}")
        else:
            # 원문 탭에는 전체 텍스트 표시 (매칭 부분 강조)
            if text:
                highlighted = self.format_text_highlight(text, match_hint)
                raw_text.setHtml(f"<pre>{highlighted}</pre>")
            elif raw_bytes:
                # 텍스트로 변환할 수 없지만 바이너리 데이터가 있는 경우
                # 추가 인코딩 시도 또는 바이너리 데이터를 텍스트로 표시 시도
                text_attempt = None
                for enc in ("latin-1", "cp1252", "iso-8859-1"):
                    try:
                        text_attempt = raw_bytes.decode(enc, errors='replace')
                        if text_attempt and len(text_attempt.strip()) > 0:
                            break
                    except:
                        continue
                
                if text_attempt and len(text_attempt.strip()) > 0:
                    # 일부 특수 문자를 제거하거나 표시 가능한 문자만 표시
                    display_text = ''.join(c if ord(c) < 128 or c.isprintable() else '.' for c in text_attempt)
                    # 하이라이팅 적용
                    highlighted = self.format_text_highlight(display_text, match_hint)
                    raw_text.setHtml(f"<pre>텍스트 변환 (부분 성공):\n{highlighted}\n\n(원본 바이너리 데이터는 HEX 탭에서 확인하세요)</pre>")
                else:
                    raw_text.setPlainText(f"텍스트로 변환할 수 없는 바이너리 데이터입니다.\n파일 크기: {len(raw_bytes)} bytes\n\nHEX 탭에서 바이너리 데이터를 확인하세요.")
            else:
                raw_text.setPlainText("텍스트 데이터가 없습니다.")

            byte_offset, encoding, match_len = self.find_byte_offset(raw_bytes, match_hint) if raw_bytes else (None, None, None)
            if raw_bytes:
                hex_view = self.format_hex_view(raw_bytes, byte_offset, encoding, show_full=True)
                hex_text.setPlainText(hex_view)
            else:
                hex_text.setPlainText("HEX 데이터가 없습니다.")

        tabs.addTab(raw_text, "원문")
        tabs.addTab(hex_text, "HEX/디코딩")

        # 매칭 위치 강조 탭
        if not error and byte_offset is not None and match_len:
            highlight = QTextEdit()
            highlight.setReadOnly(True)
            highlight.setFontFamily("Courier")
            highlight_html = self.format_hex_view_highlight(
                raw_bytes,
                byte_offset,
                match_len,
                encoding
            )
            highlight.setHtml(highlight_html)
            tabs.addTab(highlight, "매칭 위치")

        if abx_text:
            abx_tab = QTextEdit()
            abx_tab.setReadOnly(True)
            abx_tab.setFontFamily("Courier")
            abx_tab.setPlainText(abx_text)
            tabs.addTab(abx_tab, "ABX 결과")

        def get_active_text_edit():
            current = tabs.currentWidget()
            if isinstance(current, QTextEdit):
                return current
            return None

        def do_find(forward=True):
            needle = search_input.text()
            if not needle:
                return
            edit = get_active_text_edit()
            if not edit:
                return
            flags = QTextDocument.FindFlags()
            if not forward:
                flags |= QTextDocument.FindBackward
            if not edit.find(needle, flags):
                # 처음/끝으로 되돌려 다시 탐색
                cursor = edit.textCursor()
                cursor.movePosition(QTextCursor.Start if forward else QTextCursor.End)
                edit.setTextCursor(cursor)
                edit.find(needle, flags)

        btn_find_next.clicked.connect(lambda: do_find(True))
        btn_find_prev.clicked.connect(lambda: do_find(False))
        search_input.returnPressed.connect(lambda: do_find(True))

        dialog.resize(800, 600)
        dialog.exec_()

    def get_file_content_for_detail(self, file_path):
        """파일 원문/바이트 데이터 가져오기"""
        # reset_instance가 있으면 사용
        if self.reset_instance:
            try:
                if getattr(self.reset_instance, "choice", None) == "2":
                    text = self.reset_instance.adb_read_file_for_search(file_path)
                    raw_bytes = self.reset_instance.adb_read_file_bytes(file_path)
                else:
                    text = self.reset_instance.read_file_for_search(file_path)
                    raw_bytes = self.reset_instance.read_file_bytes(file_path)
                
                if text or raw_bytes:
                    return text or "", raw_bytes or b"", None
            except Exception as e:
                pass  # 실패하면 저장된 경로로 시도
        
        # reset_instance가 없거나 실패한 경우, 저장된 파일 경로로 직접 읽기 시도
        if not self.saved_file_path or not self.saved_source:
            return None, None, f"저장된 파일 경로 정보가 없습니다. (file_path={self.saved_file_path}, source={self.saved_source})"
        
        try:
            import zipfile
            import os
            
            # saved_source가 숫자 문자열인 경우 변환
            source_map = {"1": "ZIP", "2": "ADB", "3": "Folder"}
            if self.saved_source in source_map:
                self.saved_source = source_map[self.saved_source]
            
            if self.saved_source == "ZIP":
                # ZIP 파일에서 읽기
                if not os.path.exists(self.saved_file_path):
                    return None, None, f"ZIP 파일이 존재하지 않습니다: {self.saved_file_path}"
                
                if not zipfile.is_zipfile(self.saved_file_path):
                    return None, None, f"ZIP 파일이 아닙니다: {self.saved_file_path}"
                
                # 여러 경로 후보 시도
                path_candidates = [
                    file_path,  # 원본 경로
                    file_path.lstrip("/"),  # 앞의 / 제거
                    file_path.replace("Dump/", ""),  # Dump/ 제거
                    file_path.replace("Dump/", "").lstrip("/"),  # Dump/ 제거 후 / 제거
                ]
                
                if file_path.startswith("Dump/"):
                    path_candidates.append(file_path[5:])  # Dump/ 제거
                else:
                    path_candidates.append(f"Dump/{file_path}")  # Dump/ 추가
                    path_candidates.append(f"Dump/{file_path.lstrip('/')}")  # Dump/ 추가 후 / 제거
                
                with zipfile.ZipFile(self.saved_file_path, 'r') as zf:
                    zip_file_list = zf.namelist()
                    
                    for zip_path in path_candidates:
                        # 정확한 매칭 시도
                        if zip_path in zip_file_list:
                            try:
                                with zf.open(zip_path) as f:
                                    raw_bytes = f.read()
                                # 텍스트로 변환 시도
                                text = None
                                for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                                    try:
                                        text = raw_bytes.decode(enc)
                                        break
                                    except:
                                        continue
                                return text or "", raw_bytes, None
                            except Exception as e:
                                continue
                        
                        # 부분 매칭 시도 (파일명만으로)
                        file_name = os.path.basename(zip_path)
                        for zf_path in zip_file_list:
                            if zf_path.endswith(file_name) or zf_path.endswith(f"/{file_name}"):
                                try:
                                    with zf.open(zf_path) as f:
                                        raw_bytes = f.read()
                                    # 텍스트로 변환 시도
                                    text = None
                                    for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                                        try:
                                            text = raw_bytes.decode(enc)
                                            break
                                        except:
                                            continue
                                    return text or "", raw_bytes, None
                                except Exception as e:
                                    continue
                
                return None, None, f"ZIP 파일에서 파일을 찾을 수 없습니다: {file_path} (시도한 경로: {path_candidates})"
            
            elif self.saved_source == "Folder":
                # 폴더에서 직접 읽기
                # 여러 경로 후보 시도
                path_candidates = [
                    os.path.join(self.saved_file_path, file_path),
                    os.path.join(self.saved_file_path, file_path.lstrip("/")),
                    os.path.join(self.saved_file_path, file_path.replace("Dump/", "")),
                    os.path.join(self.saved_file_path, file_path.replace("Dump/", "").lstrip("/")),
                ]
                
                if file_path.startswith("Dump/"):
                    path_candidates.append(os.path.join(self.saved_file_path, file_path[5:]))
                else:
                    path_candidates.append(os.path.join(self.saved_file_path, "Dump", file_path))
                    path_candidates.append(os.path.join(self.saved_file_path, "Dump", file_path.lstrip("/")))
                
                # 파일명만으로도 시도
                file_name = os.path.basename(file_path)
                if file_name:
                    for root, dirs, files in os.walk(self.saved_file_path):
                        if file_name in files:
                            path_candidates.append(os.path.join(root, file_name))
                
                for full_path in path_candidates:
                    if os.path.exists(full_path) and os.path.isfile(full_path):
                        try:
                            with open(full_path, 'rb') as f:
                                raw_bytes = f.read()
                            # 텍스트로 변환 시도
                            text = None
                            for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                                try:
                                    text = raw_bytes.decode(enc)
                                    break
                                except:
                                    continue
                            return text or "", raw_bytes, None
                        except Exception as e:
                            continue
                
                return None, None, f"폴더에서 파일을 찾을 수 없습니다: {file_path} (시도한 경로: {path_candidates[:5]})"
            else:
                return None, None, f"지원하지 않는 소스 타입: {self.saved_source}"
        except Exception as e:
            import traceback
            return None, None, f"저장된 파일 경로에서 읽기 실패: {e}\n{traceback.format_exc()}"

    def build_text_snippet(self, text, match_hint):
        """매칭 힌트를 기준으로 주변 텍스트 추출"""
        if not text:
            return "", None

        if match_hint:
            raw_hint = str(match_hint).replace(" (시간 없음)", "")
            idx = text.find(raw_hint)
            if idx != -1:
                before = text[:idx]
                line_no = before.count("\n") + 1
                lines = text.splitlines()
                line_idx = max(0, line_no - 1)
                start = max(0, line_idx - 3)
                end = min(len(lines), line_idx + 4)
                snippet = "\n".join(lines[start:end])
                return snippet, line_no

        # 힌트를 못 찾으면 전체 표시
        return text, None

    def find_byte_offset(self, raw_bytes, match_hint):
        """바이트 오프셋과 인코딩/길이 추정"""
        if not raw_bytes or not match_hint:
            return None, None, None

        raw_hint = str(match_hint).replace(" (시간 없음)", "")
        for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
            try:
                encoded = raw_hint.encode(enc)
                pos = raw_bytes.find(encoded)
                if pos != -1:
                    return pos, enc, len(encoded)
            except Exception:
                continue

        return None, None, None

    def get_deep_search_raw_data(self, file_path, match_value):
        """Find original data for deep search results from file"""
        # reset_instance가 있으면 사용
        if self.reset_instance:
            try:
                if getattr(self.reset_instance, "choice", None) == "2":
                    content = self.reset_instance.adb_read_file_for_search(file_path)
                    raw_bytes = self.reset_instance.adb_read_file_bytes(file_path)
                else:
                    content = self.reset_instance.read_file_for_search(file_path)
                    raw_bytes = self.reset_instance.read_file_bytes(file_path)
                
                if content or raw_bytes:
                    return (content or "", raw_bytes or b""), None
            except Exception as e:
                pass  # 실패하면 저장된 경로로 시도
        
        # reset_instance가 없거나 실패한 경우, 저장된 파일 경로로 직접 읽기 시도
        if self.saved_file_path and self.saved_source:
            try:
                import zipfile
                import os
                
                # saved_source가 숫자 문자열인 경우 변환
                source_map = {"1": "ZIP", "2": "ADB", "3": "Folder"}
                if self.saved_source in source_map:
                    self.saved_source = source_map[self.saved_source]
                
                if self.saved_source == "ZIP":
                    # ZIP 파일에서 읽기
                    if os.path.exists(self.saved_file_path) and zipfile.is_zipfile(self.saved_file_path):
                        with zipfile.ZipFile(self.saved_file_path, 'r') as zf:
                            # Dump/ 접두사 제거 시도
                            zip_path = file_path
                            if zip_path.startswith("Dump/"):
                                zip_path = zip_path[5:]
                            elif not zip_path.startswith("Dump/") and not zip_path.startswith("/"):
                                zip_path = f"Dump/{zip_path}"
                            
                            try:
                                with zf.open(zip_path) as f:
                                    raw_bytes = f.read()
                                    # 텍스트로 변환 시도
                                    content = None
                                    for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                                        try:
                                            content = raw_bytes.decode(enc)
                                            break
                                        except:
                                            continue
                                    return (content or "", raw_bytes), None
                            except:
                                pass
                
                elif self.saved_source == "Folder":
                    # 폴더에서 직접 읽기
                    full_path = os.path.join(self.saved_file_path, file_path)
                    if os.path.exists(full_path):
                        try:
                            with open(full_path, 'rb') as f:
                                raw_bytes = f.read()
                            # 텍스트로 변환 시도
                            content = None
                            for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                                try:
                                    content = raw_bytes.decode(enc)
                                    break
                                except:
                                    continue
                            return (content or "", raw_bytes), None
                        except Exception as e:
                            return None, f"저장된 파일 경로에서 읽기 실패: {e}"
            except Exception as e:
                return None, f"저장된 파일 경로에서 읽기 실패: {e}"
        
        return None, "분석 인스턴스가 없고 저장된 파일 경로도 사용할 수 없습니다."

    def build_binary_patterns(self, time_dt):
        """시간 값을 바이너리 패턴으로 변환"""
        patterns = {}
        epoch_sec = int(time_dt.timestamp())
        epoch_ms = int(time_dt.timestamp() * 1000)

        # 32-bit/64-bit seconds
        patterns["epoch_sec_le32"] = struct.pack("<I", epoch_sec & 0xFFFFFFFF)
        patterns["epoch_sec_be32"] = struct.pack(">I", epoch_sec & 0xFFFFFFFF)
        patterns["epoch_sec_le64"] = struct.pack("<Q", epoch_sec)
        patterns["epoch_sec_be64"] = struct.pack(">Q", epoch_sec)

        # 64-bit milliseconds
        patterns["epoch_ms_le64"] = struct.pack("<Q", epoch_ms)
        patterns["epoch_ms_be64"] = struct.pack(">Q", epoch_ms)

        return patterns

    def get_file_mod_time_for_search(self, file_path):
        """Get file modification time for deep search"""
        try:
            if getattr(self, "choice", None) == "2":
                return self.adb_get_mod_time(file_path)
            return self.get_mod_time_from_zip(file_path)
        except Exception:
            return None

    def format_hex_view(self, raw_bytes, byte_offset=None, encoding=None, context_size=128, show_full=False):
        """HEX + ASCII 형태로 원문 데이터를 보기 좋게 포맷"""
        if not raw_bytes:
            return "HEX 데이터를 생성할 수 없습니다."

        if show_full:
            start = 0
        elif byte_offset is None:
            start = 0
        else:
            start = max(0, byte_offset - context_size)
        end = len(raw_bytes) if show_full else min(len(raw_bytes), start + (context_size * 2))
        chunk = raw_bytes[start:end]

        lines = []
        header = f"바이트 범위: {start} ~ {end} (인코딩 추정: {encoding or '알 수 없음'})"
        lines.append(header)
        lines.append("")

        for i in range(0, len(chunk), 16):
            line_bytes = chunk[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in line_bytes)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
            lines.append(f"{start + i:08X}  {hex_part:<47}  {ascii_part}")

        return "\n".join(lines)

    def format_hex_view_highlight(self, raw_bytes, offset, length, encoding, context_size=64):
        """HEX + ASCII 형태로 매칭 위치 강조 (HTML)"""
        if not raw_bytes or offset is None or not length:
            return "<pre>매칭 위치를 표시할 수 없습니다.</pre>"

        start = max(0, offset - context_size)
        end = min(len(raw_bytes), offset + length + context_size)
        chunk = raw_bytes[start:end]

        lines = []
        header = f"바이트 범위: {start} ~ {end} (인코딩 추정: {encoding or '알 수 없음'})"
        lines.append(header)
        lines.append("")

        highlight_start = offset - start
        highlight_end = highlight_start + length

        for i in range(0, len(chunk), 16):
            line_bytes = chunk[i:i+16]
            hex_parts = []
            ascii_parts = []
            for j, b in enumerate(line_bytes):
                idx = i + j
                in_hl = highlight_start <= idx < highlight_end
                hx = f"{b:02X}"
                ch = chr(b) if 32 <= b <= 126 else "."
                if in_hl:
                    hex_parts.append(f"<span style='background-color:#ffe66b;font-weight:bold'>{hx}</span>")
                    ascii_parts.append(f"<span style='background-color:#ffe66b;font-weight:bold'>{ch}</span>")
                else:
                    hex_parts.append(hx)
                    ascii_parts.append(ch)
            hex_part = " ".join(hex_parts)
            ascii_part = "".join(ascii_parts)
            lines.append(f"{start + i:08X}  {hex_part:<47}  {ascii_part}")

        html = "<pre>" + "\n".join(lines) + "</pre>"
        return html

    def format_text_highlight(self, text, match_hint):
        """원문 텍스트에서 매칭 문자열 강조 (HTML)"""
        escaped = html.escape(text or "")
        if not match_hint:
            return escaped
        
        needle = html.escape(str(match_hint).replace(" (시간 없음)", ""))
        if not needle:
            return escaped
        
        # persistent_properties의 경우: reboot,factory_reset,숫자 패턴도 하이라이팅
        # match_hint가 숫자만 있는 경우 reboot,factory_reset,숫자 패턴 찾기
        if re.match(r'^\d{10,}$', needle):
            # 숫자만 있는 경우, reboot,factory_reset,숫자 패턴도 하이라이팅
            persistent_pattern = rf"reboot,factory_reset,{re.escape(needle)}"
            try:
                pattern = re.compile(persistent_pattern, re.IGNORECASE)
                escaped = pattern.sub(r"<span style='background-color:#ffe66b;font-weight:bold'>\g<0></span>", escaped)
            except Exception:
                pass
        
        # 기본 매칭 문자열 강조
        try:
            pattern = re.compile(re.escape(needle), re.IGNORECASE)
            escaped = pattern.sub(r"<span style='background-color:#ffe66b;font-weight:bold'>\g<0></span>", escaped)
        except Exception:
            pass
        
        return escaped
    
    def update_deep_search_progress(self, current, total):
        """Update deep search progress"""
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            # 진행률 텍스트 표시
            percentage = int((current / total) * 100) if total > 0 else 0
            remaining = total - current
            self.progress_bar.setFormat(f"Deep Search in progress... {current}/{total} ({percentage}%) - Remaining files: {remaining}")
        else:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setFormat("Deep Search in progress...")
    
    def deep_search_finished(self):
        """Handle deep search completion"""
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("")  # 진행률 텍스트 초기화
        self.btn_deep_search.setEnabled(True)
        
        # Move to deep search results tab
        for i in range(self.result_tabs.count()):
            if self.result_tabs.tabText(i) == "Deep Search Results":
                self.result_tabs.setCurrentIndex(i)
                break
        
        # Deep search results are saved together with analysis results, so no separate save needed
        # (사용자가 수동으로 저장할 수 있음)
    
    def _convert_to_json_serializable(self, obj):
        """datetime 객체를 JSON 직렬화 가능한 형태로 변환"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._convert_to_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            # 기타 타입은 문자열로 변환
            return str(obj)
    
    def save_analysis_result(self):
        """분석 결과를 JSON 파일로 저장"""
        try:
            # 저장할 데이터 구성 (파일명은 나중에 추가)
            save_data = {
                'timestamp': datetime.now().isoformat(),
                'file_path': self.file_path_edit.text() if hasattr(self, 'file_path_edit') else '',
                'source': self.get_selected_source() if hasattr(self, 'get_selected_source') else '',
                'artifact_data': {},
                'deep_search_results': [],
                'confirmed_time': self.confirmed_time_value if hasattr(self, 'confirmed_time_value') else None,
                'saved_filename': None,  # 사용자가 지정한 파일명
                'order': '',  # 차수 (파일명에서 파싱)
                'manufacturer': '',  # 제조사 (파일명에서 파싱)
                'model_name': '',  # 모델명 (파일명에서 파싱)
                'scenario': '',  # 시나리오명 (파일명에서 파싱)
                'memo': ''  # 메모 (사용자 입력)
            }
            
            # 아티팩트 데이터 저장
            if hasattr(self, 'artifact_data') and self.artifact_data:
                for artifact_id, data_list in self.artifact_data.items():
                    save_data['artifact_data'][artifact_id] = []
                    for data in data_list:
                        # 모든 필드를 JSON 직렬화 가능한 형태로 변환
                        item_data = {
                            'name': data.get('name'),
                            'path': data.get('path'),
                            'time': None,
                            'message': data.get('message'),
                            'is_kst': data.get('is_kst', False),
                            'original_time': data.get('original_time')
                        }
                        
                        # time 필드 처리
                        time_value = data.get('time')
                        if time_value:
                            if isinstance(time_value, datetime):
                                item_data['time'] = time_value.isoformat()
                            else:
                                item_data['time'] = str(time_value)
                        
                        # original_time도 datetime일 수 있으므로 변환
                        if item_data['original_time'] and isinstance(item_data['original_time'], datetime):
                            item_data['original_time'] = item_data['original_time'].isoformat()
                        
                        save_data['artifact_data'][artifact_id].append(item_data)
            else:
                self.log("[결과 저장] 아티팩트 데이터가 없습니다. 빈 결과로 저장합니다.")
            
            # Save deep search results
            if hasattr(self, 'deep_search_table') and self.deep_search_table:
                for row in range(self.deep_search_table.rowCount()):
                    search_time = self.deep_search_table.item(row, 0).text() if self.deep_search_table.item(row, 0) else ""
                    file_path = self.deep_search_table.item(row, 1).text() if self.deep_search_table.item(row, 1) else ""
                    match_format = self.deep_search_table.item(row, 2).text() if self.deep_search_table.item(row, 2) else ""
                    match_value = self.deep_search_table.item(row, 3).text() if self.deep_search_table.item(row, 3) else ""
                    save_data['deep_search_results'].append({
                        'search_time': search_time,
                        'file_path': file_path,
                        'match_format': match_format,
                        'match_value': match_value
                    })
            
            # 결과 디렉토리 생성
            results_dir = os.path.join(os.path.dirname(__file__), "saved_results")
            try:
                os.makedirs(results_dir, exist_ok=True)
                self.log(f"[결과 저장] 디렉토리 확인: {results_dir}")
            except Exception as e:
                self.log(f"[결과 저장] 디렉토리 생성 실패: {e}")
                return
            
            # 파일명 입력 받기 (포맷: N차 제조사 모델명 N번)
            memo_text = ''  # 메모 변수 초기화
            try:
                filename_dialog = QDialog(self)
                filename_dialog.setWindowTitle("결과 저장")
                filename_dialog.setMinimumWidth(500)
                
                layout = QVBoxLayout()
                filename_dialog.setLayout(layout)
                
                # 설명 레이블
                info_label = QLabel("파일명을 입력하세요 (포맷: N차 또는 ExN 제조사 모델명 시나리오명)\n예: 1차 삼성 SM-S921N 공장초기화 또는 Ex1 삼성 SM-S921N 공장초기화")
                info_label.setWordWrap(True)
                layout.addWidget(info_label)
                
                # 기존 데이터에서 선택할 수 있는 콤보박스 추가
                # 먼저 기존 데이터 로드
                existing_orders = set()
                existing_manufacturers = set()
                existing_models = set()
                existing_scenarios = set()
                
                try:
                    results_dir = os.path.join(os.path.dirname(__file__), "saved_results")
                    if os.path.exists(results_dir):
                        for filename in os.listdir(results_dir):
                            if not filename.endswith('.json'):
                                continue
                            try:
                                filepath = os.path.join(results_dir, filename)
                                with open(filepath, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                saved_filename = data.get('saved_filename', filename)
                                display_name = saved_filename.replace('.json', '')
                                
                                # 파일명 파싱
                                parts = display_name.split()
                                if len(parts) >= 1:
                                    # Check for order pattern: "N차" or "ExN" format
                                    if '차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit()):
                                        existing_orders.add(parts[0])
                                        if len(parts) >= 2:
                                            existing_manufacturers.add(parts[1])
                                        if len(parts) >= 3:
                                            existing_models.add(parts[2])
                                        if len(parts) >= 4:
                                            existing_scenarios.add(' '.join(parts[3:]))
                            except:
                                continue
                except:
                    pass
                
                # 입력 필드들
                form_layout = QVBoxLayout()
                
                # 차수
                order_layout = QHBoxLayout()
                order_layout.addWidget(QLabel("차수:"))
                order_combo = QComboBox()
                order_combo.setEditable(True)
                order_combo.setInsertPolicy(QComboBox.NoInsert)
                order_combo.addItem("")
                order_combo.addItems(sorted(existing_orders))
                order_layout.addWidget(order_combo)
                form_layout.addLayout(order_layout)
                
                # 제조사
                manufacturer_layout = QHBoxLayout()
                manufacturer_layout.addWidget(QLabel("제조사:"))
                manufacturer_combo = QComboBox()
                manufacturer_combo.setEditable(True)
                manufacturer_combo.setInsertPolicy(QComboBox.NoInsert)
                manufacturer_combo.addItem("")
                manufacturer_combo.addItems(sorted(existing_manufacturers))
                manufacturer_layout.addWidget(manufacturer_combo)
                form_layout.addLayout(manufacturer_layout)
                
                # 모델명
                model_layout = QHBoxLayout()
                model_layout.addWidget(QLabel("모델명:"))
                model_combo = QComboBox()
                model_combo.setEditable(True)
                model_combo.setInsertPolicy(QComboBox.NoInsert)
                model_combo.addItem("")
                model_combo.addItems(sorted(existing_models))
                model_layout.addWidget(model_combo)
                form_layout.addLayout(model_layout)
                
                # 시나리오명
                scenario_layout = QHBoxLayout()
                scenario_layout.addWidget(QLabel("시나리오명:"))
                scenario_combo = QComboBox()
                scenario_combo.setEditable(True)
                scenario_combo.setInsertPolicy(QComboBox.NoInsert)
                scenario_combo.addItem("")
                scenario_combo.addItems(sorted(existing_scenarios))
                scenario_layout.addWidget(scenario_combo)
                form_layout.addLayout(scenario_layout)
                
                layout.addLayout(form_layout)
                
                # 메모 입력 필드 추가
                memo_label = QLabel("메모 (선택사항):")
                memo_label.setStyleSheet("font-weight: bold;")
                layout.addWidget(memo_label)
                
                memo_edit = QTextEdit()
                memo_edit.setPlaceholderText("추가 메모를 입력하세요...")
                memo_edit.setMaximumHeight(80)
                layout.addWidget(memo_edit)
                
                # 미리보기
                preview_label = QLabel("파일명 미리보기:")
                preview_label.setStyleSheet("font-weight: bold;")
                layout.addWidget(preview_label)
                
                preview_text = QLineEdit()
                preview_text.setReadOnly(True)
                preview_text.setStyleSheet("background-color: #f0f0f0;")
                layout.addWidget(preview_text)
                
                def update_preview():
                    """미리보기 업데이트"""
                    try:
                        parts = []
                        if order_combo.currentText().strip():
                            parts.append(order_combo.currentText().strip())
                        if manufacturer_combo.currentText().strip():
                            parts.append(manufacturer_combo.currentText().strip())
                        if model_combo.currentText().strip():
                            parts.append(model_combo.currentText().strip())
                        if scenario_combo.currentText().strip():
                            parts.append(scenario_combo.currentText().strip())
                        
                        if parts:
                            preview = " ".join(parts)
                        else:
                            preview = "(입력 필요)"
                        preview_text.setText(preview)
                    except:
                        pass
                
                try:
                    order_combo.currentTextChanged.connect(update_preview)
                    manufacturer_combo.currentTextChanged.connect(update_preview)
                    model_combo.currentTextChanged.connect(update_preview)
                    scenario_combo.currentTextChanged.connect(update_preview)
                except:
                    pass
                
                # 버튼
                button_layout = QHBoxLayout()
                button_layout.addStretch()
                
                btn_cancel = QPushButton("취소")
                btn_cancel.clicked.connect(filename_dialog.reject)
                button_layout.addWidget(btn_cancel)
                
                btn_ok = QPushButton("저장")
                btn_ok.clicked.connect(filename_dialog.accept)
                btn_ok.setDefault(True)
                button_layout.addWidget(btn_ok)
                
                layout.addLayout(button_layout)
                
                # 다이얼로그 실행
                if filename_dialog.exec_() != QDialog.Accepted:
                    self.log("[결과 저장] 저장이 취소되었습니다.")
                    return
                
                # 파일명 조합
                parts = []
                try:
                    if order_combo.currentText().strip():
                        parts.append(order_combo.currentText().strip())
                    if manufacturer_combo.currentText().strip():
                        parts.append(manufacturer_combo.currentText().strip())
                    if model_combo.currentText().strip():
                        parts.append(model_combo.currentText().strip())
                    if scenario_combo.currentText().strip():
                        parts.append(scenario_combo.currentText().strip())
                except:
                    pass
                
                if not parts:
                    self.show_message("오류", "최소 하나의 필드는 입력해야 합니다.")
                    return
                
                filename = " ".join(parts)
                
                # 메모 가져오기
                try:
                    memo_text = memo_edit.toPlainText().strip()
                except:
                    memo_text = ''
            except Exception as e:
                import traceback
                error_msg = f"[파일명 입력 다이얼로그 오류] {str(e)}\n{traceback.format_exc()}"
                self.log(error_msg)
                # 오류 발생 시 기본 파일명 사용
                filename = f"analysis_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                self.log(f"[결과 저장] 오류로 인해 기본 파일명 사용: {filename}")
            
            # 확장자 처리
            if not filename.endswith('.json'):
                filename += '.json'
            
            # 저장 데이터에 파일명 추가
            save_data['saved_filename'] = filename
            
            # 파일명에서 정보 파싱하여 저장
            parts = filename.replace('.json', '').split()
            order = ''
            manufacturer = ''
            model_name = ''
            scenario = ''
            
            if len(parts) >= 1:
                # Check for order pattern: "N차" or "ExN" format
                if '차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit()):
                    order = parts[0]
                    if len(parts) >= 2:
                        manufacturer = parts[1]
                    if len(parts) >= 3:
                        model_name = parts[2]
                    if len(parts) >= 4:
                        scenario = ' '.join(parts[3:])
            
            save_data['order'] = order
            save_data['manufacturer'] = manufacturer
            save_data['model_name'] = model_name
            save_data['scenario'] = scenario
            
            # 메모 저장
            try:
                save_data['memo'] = memo_text
            except:
                save_data['memo'] = ''
            
            filepath = os.path.join(results_dir, filename)
            
            # 파일이 이미 존재하는지 확인
            if os.path.exists(filepath):
                reply = self.show_question("파일 존재", f"'{filename}' 파일이 이미 존재합니다.\n덮어쓰시겠습니까?")
                if reply != QMessageBox.Yes:
                    self.log("[결과 저장] 저장이 취소되었습니다.")
                    return
                # 덮어쓰기 확인만 하고 계속 진행
            
            self.log(f"[결과 저장] 저장 시도: {filepath}")
            
            # JSON 직렬화 가능한 형태로 변환 (모든 datetime 객체 처리)
            serializable_data = self._convert_to_json_serializable(save_data)
            
            # JSON 파일로 저장
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, ensure_ascii=False, indent=2)
            
            self.log(f"[결과 저장 성공] {filename}")
            self.log(f"[저장 위치] {results_dir}")
            
            # 저장된 결과 목록 새로고침 (예외 처리 추가)
            if hasattr(self, 'load_saved_results'):
                try:
                    self.load_saved_results()
                except Exception as load_error:
                    self.log(f"[결과 목록 새로고침 실패] {load_error}")
        except Exception as e:
            import traceback
            error_msg = f"[결과 저장 실패] {str(e)}\n{traceback.format_exc()}"
            self.log(error_msg)
            try:
                msg_box = CopyableMessageBox(self, "저장 오류", f"결과 저장 중 오류가 발생했습니다:\n{str(e)}")
                msg_box.exec_()
            except:
                pass  # GUI가 아직 준비되지 않았을 수 있음
    
    def show_saved_results(self):
        """저장된 결과 파일 탐색기 스타일로 보기 (별도 창)"""
        explorer = SavedResultsExplorer(self)
        explorer.exec_()
    
    def load_saved_results(self):
        """저장된 결과 목록 로드 (메인 화면 트리)"""
        try:
            if not hasattr(self, 'saved_results_tree') or not self.saved_results_tree:
                return
            
            self.saved_results_tree.clear()
            
            results_dir = os.path.join(os.path.dirname(__file__), "saved_results")
            if not os.path.exists(results_dir):
                try:
                    os.makedirs(results_dir, exist_ok=True)
                except:
                    pass
                return
            
            # 파일명 기반으로 그룹화 (차수/모델명 추출)
            file_list = []
            try:
                for filename in os.listdir(results_dir):
                    if not filename.endswith('.json'):
                        continue
                    
                    filepath = os.path.join(results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # 사용자가 지정한 파일명 사용 (없으면 실제 파일명 사용)
                        saved_filename = data.get('saved_filename', filename)
                        display_name = saved_filename.replace('.json', '')
                        
                        # 파일명 파싱
                        parts = display_name.split()
                        order = '기타'
                        manufacturer = ''
                        model = ''
                        scenario = ''
                        
                        if len(parts) >= 1:
                            # Check for order pattern: "N차" or "ExN" format
                            if '차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit()):
                                order = parts[0]
                                remaining = parts[1:] if len(parts) > 1 else []
                            else:
                                remaining = parts
                            
                            if len(remaining) >= 3:
                                manufacturer = remaining[0]
                                model = remaining[1]
                                scenario = ' '.join(remaining[2:])
                            elif len(remaining) == 2:
                                manufacturer = remaining[0]
                                model = remaining[1]
                            elif len(remaining) == 1:
                                model = remaining[0]
                        
                        file_info = {
                            'filename': filename,
                            'filepath': filepath,
                            'data': data,
                            'display_name': display_name,
                            'order': order,
                            'manufacturer': manufacturer,
                            'model': model,
                            'scenario': scenario
                        }
                        file_list.append(file_info)
                        
                        # 디버깅: 첫 번째 파일 정보 로그
                        if len(file_list) == 1:
                            try:
                                self.log(f"[필터 디버깅] 첫 번째 파일 파싱 결과:")
                                self.log(f"  파일명: {display_name}")
                                self.log(f"  Order: '{order}', Manufacturer: '{manufacturer}', 모델명: '{model}', 시나리오: '{scenario}'")
                            except:
                                pass
                    except Exception as e:
                        continue
            except Exception as e:
                return  # 디렉토리 읽기 실패 시 조용히 반환
            
            # 전체 데이터 저장 (필터링용)
            self.all_saved_results = file_list
            
            # 필터 콤보박스 업데이트 (안전하게)
            # 콤보박스가 초기화되었는지 확인
            try:
                has_order_combo = hasattr(self, 'filter_order_combo') and self.filter_order_combo is not None
                self.log(f"[필터 디버깅] 콤보박스 존재 여부 확인: {has_order_combo}")
                
                if has_order_combo:
                    self.log("[필터 디버깅] update_filter_combos() 호출 시작")
                    self.update_filter_combos()
                    self.log("[필터 디버깅] update_filter_combos() 호출 완료")
                else:
                    self.log("[필터 디버깅] filter_order_combo가 없거나 초기화되지 않음 - QTimer로 지연 업데이트")
                    # QTimer를 사용하여 나중에 업데이트 시도
                    from PyQt5.QtCore import QTimer
                    QTimer.singleShot(200, lambda: self._delayed_filter_update())
            except Exception as e:
                import traceback
                try:
                    self.log(f"[필터 콤보박스 업데이트 오류] {str(e)}\n{traceback.format_exc()}")
                except:
                    pass
            
            # 파일명에서 차수, 제조사, 모델명 추출하여 그룹화
            # 포맷: "N차 제조사 모델명 시나리오명"
            groups = {}
            for file_info in file_list:
                display_name = file_info['display_name']
                
                # 공백으로 분리
                parts = display_name.split()
                
                # 차수 추출 (첫 번째 부분이 "N차" 형식인지 확인)
                order = '기타'
                manufacturer = ''
                model = ''
                
                if len(parts) >= 1:
                    # 첫 번째 부분이 차수인지 확인 (예: "1차", "2차", "Ex1", "Ex2")
                    if '차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit()):
                        order = parts[0]
                        remaining = parts[1:] if len(parts) > 1 else []
                    else:
                        remaining = parts
                    
                    # 나머지 부분에서 제조사, 모델명, 시나리오명 추출
                    if len(remaining) >= 3:
                        # 제조사, 모델명, 시나리오명이 모두 있는 경우
                        manufacturer = remaining[0]
                        model = remaining[1]
                        # 시나리오명은 나머지 전체 (여러 단어일 수 있음)
                    elif len(remaining) == 2:
                        # 제조사와 모델명만 있는 경우
                        manufacturer = remaining[0]
                        model = remaining[1]
                    elif len(remaining) == 1:
                        # 모델명만 있는 경우
                        manufacturer = ''
                        model = remaining[0]
                    else:
                        manufacturer = ''
                        model = ''
                    
                    # 모델명이 없으면 전체를 모델명으로
                    if not model:
                        model = display_name
                else:
                    model = display_name
                
                # 그룹화 키 생성 (차수 + 제조사 + 모델명, 시나리오명은 제외)
                if manufacturer:
                    group_key = f"{order} {manufacturer} {model}".strip()
                else:
                    group_key = f"{order} {model}".strip()
                
                if order not in groups:
                    groups[order] = {}
                if group_key not in groups[order]:
                    groups[order][group_key] = []
                
                groups[order][group_key].append(file_info)
            
            # 트리 구성
            for order in sorted(groups.keys()):
                order_item = QTreeWidgetItem(self.saved_results_tree)
                order_item.setText(0, order)
                order_item.setExpanded(True)
                
                for model in sorted(groups[order].keys()):
                    model_item = QTreeWidgetItem(order_item)
                    model_item.setText(0, model)
                    model_item.setExpanded(True)
                    
                    # 해당 모델의 파일들
                    for file_info in groups[order][model]:
                        result_item = QTreeWidgetItem(model_item)
                        result_item.setText(0, file_info['display_name'])
                        result_item.setData(0, Qt.UserRole, file_info['filepath'])
                        result_item.setData(0, Qt.UserRole + 1, file_info['data'])
        except Exception as e:
            import traceback
            error_msg = f"[저장된 결과 로드 실패] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass  # log 함수가 없을 수 있음
    
    def update_filter_combos(self):
        """필터 콤보박스에 고유값 목록 업데이트"""
        try:
            if not hasattr(self, 'all_saved_results'):
                try:
                    self.log("[필터 업데이트] all_saved_results 속성이 없습니다.")
                except:
                    pass
                return
            
            if not self.all_saved_results:
                try:
                    self.log("[필터 업데이트] all_saved_results가 비어있습니다.")
                except:
                    pass
                return
            
            # 고유값 추출
            unique_orders = set()
            unique_manufacturers = set()
            unique_models = set()
            unique_scenarios = set()
            
            for file_info in self.all_saved_results:
                try:
                    order = file_info.get('order', '').strip()
                    manufacturer = file_info.get('manufacturer', '').strip()
                    model = file_info.get('model', '').strip()
                    scenario = file_info.get('scenario', '').strip()
                    
                    if order:
                        unique_orders.add(order)
                    if manufacturer:
                        unique_manufacturers.add(manufacturer)
                    if model:
                        unique_models.add(model)
                    if scenario:
                        unique_scenarios.add(scenario)
                except Exception as e:
                    try:
                        self.log(f"[필터 업데이트] 파일 정보 처리 오류: {str(e)}")
                    except:
                        pass
                    continue
            
            # 디버깅: 추출된 고유값 로그
            try:
                self.log(f"[필터 업데이트] 전체 파일: {len(self.all_saved_results)}개")
                self.log(f"[필터 업데이트] 차수: {len(unique_orders)}개 {list(unique_orders)[:5]}, 제조사: {len(unique_manufacturers)}개 {list(unique_manufacturers)[:5]}, 모델명: {len(unique_models)}개 {list(unique_models)[:5]}, 시나리오: {len(unique_scenarios)}개 {list(unique_scenarios)[:5]}")
            except:
                pass
            
            # 콤보박스 업데이트 (현재 선택값 유지)
            try:
                has_order = hasattr(self, 'filter_order_combo') and self.filter_order_combo is not None
                self.log(f"[필터 업데이트] 차수 콤보박스 존재 여부: {has_order}, 타입: {type(self.filter_order_combo) if hasattr(self, 'filter_order_combo') else 'None'}")
            except:
                pass
            
            if hasattr(self, 'filter_order_combo') and self.filter_order_combo is not None:
                try:
                    self.log(f"[필터 업데이트] 차수 콤보박스 업데이트 시작: {len(unique_orders)}개 항목, 값: {list(unique_orders)}")
                    current_order = self.filter_order_combo.currentText()
                    self.filter_order_combo.blockSignals(True)  # 시그널 차단
                    self.filter_order_combo.clear()
                    self.log(f"[필터 업데이트] 차수 콤보박스 clear 완료")
                    self.filter_order_combo.addItem("")  # 빈 항목 추가 (전체)
                    self.log(f"[필터 업데이트] 차수 콤보박스 빈 항목 추가 완료")
                    sorted_orders = sorted(unique_orders)
                    self.log(f"[필터 업데이트] 차수 정렬된 목록: {sorted_orders}")
                    self.filter_order_combo.addItems(sorted_orders)
                    self.log(f"[필터 업데이트] 차수 콤보박스 항목 추가 완료, 현재 개수: {self.filter_order_combo.count()}")
                    # 이전 선택값 복원
                    index = self.filter_order_combo.findText(current_order)
                    if index >= 0:
                        self.filter_order_combo.setCurrentIndex(index)
                    else:
                        self.filter_order_combo.setCurrentIndex(0)
                    self.filter_order_combo.blockSignals(False)  # 시그널 재개
                    self.log(f"[필터 업데이트] 차수 콤보박스 업데이트 완료: {self.filter_order_combo.count()}개 항목")
                except Exception as e:
                    import traceback
                    try:
                        self.log(f"[필터 업데이트] 차수 콤보박스 오류: {str(e)}\n{traceback.format_exc()}")
                    except:
                        pass
            else:
                try:
                    self.log(f"[필터 업데이트] 차수 콤보박스가 없거나 초기화되지 않음 (hasattr={hasattr(self, 'filter_order_combo')}, is_not_none={self.filter_order_combo is not None if hasattr(self, 'filter_order_combo') else False})")
                except:
                    pass
            
            if hasattr(self, 'filter_manufacturer_combo') and self.filter_manufacturer_combo is not None:
                try:
                    self.log(f"[필터 업데이트] 제조사 콤보박스 업데이트 시작: {len(unique_manufacturers)}개 항목")
                    current_manufacturer = self.filter_manufacturer_combo.currentText()
                    self.filter_manufacturer_combo.blockSignals(True)
                    self.filter_manufacturer_combo.clear()
                    self.filter_manufacturer_combo.addItem("")
                    self.filter_manufacturer_combo.addItems(sorted(unique_manufacturers))
                    index = self.filter_manufacturer_combo.findText(current_manufacturer)
                    if index >= 0:
                        self.filter_manufacturer_combo.setCurrentIndex(index)
                    else:
                        self.filter_manufacturer_combo.setCurrentIndex(0)
                    self.filter_manufacturer_combo.blockSignals(False)
                    self.log(f"[필터 업데이트] 제조사 콤보박스 업데이트 완료: {self.filter_manufacturer_combo.count()}개 항목")
                except Exception as e:
                    import traceback
                    try:
                        self.log(f"[필터 업데이트] 제조사 콤보박스 오류: {str(e)}\n{traceback.format_exc()}")
                    except:
                        pass
            else:
                try:
                    self.log(f"[필터 업데이트] 제조사 콤보박스가 없거나 초기화되지 않음")
                except:
                    pass
            
            if hasattr(self, 'filter_model_combo') and self.filter_model_combo is not None:
                try:
                    self.log(f"[필터 업데이트] 모델명 콤보박스 업데이트 시작: {len(unique_models)}개 항목")
                    current_model = self.filter_model_combo.currentText()
                    self.filter_model_combo.blockSignals(True)
                    self.filter_model_combo.clear()
                    self.filter_model_combo.addItem("")
                    self.filter_model_combo.addItems(sorted(unique_models))
                    index = self.filter_model_combo.findText(current_model)
                    if index >= 0:
                        self.filter_model_combo.setCurrentIndex(index)
                    else:
                        self.filter_model_combo.setCurrentIndex(0)
                    self.filter_model_combo.blockSignals(False)
                    self.log(f"[필터 업데이트] 모델명 콤보박스 업데이트 완료: {self.filter_model_combo.count()}개 항목")
                except Exception as e:
                    import traceback
                    try:
                        self.log(f"[필터 업데이트] 모델명 콤보박스 오류: {str(e)}\n{traceback.format_exc()}")
                    except:
                        pass
            else:
                try:
                    self.log(f"[필터 업데이트] 모델명 콤보박스가 없거나 초기화되지 않음")
                except:
                    pass
            
            if hasattr(self, 'filter_scenario_combo') and self.filter_scenario_combo is not None:
                try:
                    self.log(f"[필터 업데이트] 시나리오 콤보박스 업데이트 시작: {len(unique_scenarios)}개 항목")
                    current_scenario = self.filter_scenario_combo.currentText()
                    self.filter_scenario_combo.blockSignals(True)
                    self.filter_scenario_combo.clear()
                    self.filter_scenario_combo.addItem("")
                    self.filter_scenario_combo.addItems(sorted(unique_scenarios))
                    index = self.filter_scenario_combo.findText(current_scenario)
                    if index >= 0:
                        self.filter_scenario_combo.setCurrentIndex(index)
                    else:
                        self.filter_scenario_combo.setCurrentIndex(0)
                    self.filter_scenario_combo.blockSignals(False)
                    self.log(f"[필터 업데이트] 시나리오 콤보박스 업데이트 완료: {self.filter_scenario_combo.count()}개 항목")
                except Exception as e:
                    import traceback
                    try:
                        self.log(f"[필터 업데이트] 시나리오 콤보박스 오류: {str(e)}\n{traceback.format_exc()}")
                    except:
                        pass
            else:
                try:
                    self.log(f"[필터 업데이트] 시나리오 콤보박스가 없거나 초기화되지 않음")
                except:
                    pass
        except Exception as e:
            import traceback
            error_msg = f"[필터 콤보박스 업데이트 오류] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass
    
    def filter_saved_results(self):
        """저장된 결과 필터링"""
        try:
            if not hasattr(self, 'all_saved_results') or not self.all_saved_results:
                return
            
            # 필터 값 가져오기 (안전하게)
            filter_order = ''
            filter_manufacturer = ''
            filter_model = ''
            filter_scenario = ''
            
            try:
                if hasattr(self, 'filter_order_combo') and self.filter_order_combo is not None:
                    filter_order = self.filter_order_combo.currentText().strip().lower()
            except:
                pass
            
            try:
                if hasattr(self, 'filter_manufacturer_combo') and self.filter_manufacturer_combo is not None:
                    filter_manufacturer = self.filter_manufacturer_combo.currentText().strip().lower()
            except:
                pass
            
            try:
                if hasattr(self, 'filter_model_combo') and self.filter_model_combo is not None:
                    filter_model = self.filter_model_combo.currentText().strip().lower()
            except:
                pass
            
            try:
                if hasattr(self, 'filter_scenario_combo') and self.filter_scenario_combo is not None:
                    filter_scenario = self.filter_scenario_combo.currentText().strip().lower()
            except:
                pass
            
            # 필터링 적용
            filtered_list = []
            for file_info in self.all_saved_results:
                order = str(file_info.get('order', '')).strip().lower()
                manufacturer = str(file_info.get('manufacturer', '')).strip().lower()
                model = str(file_info.get('model', '')).strip().lower()
                scenario = str(file_info.get('scenario', '')).strip().lower()
                
                # 필터 조건 확인 (빈 문자열이면 필터 무시)
                match = True
                
                if filter_order:
                    if filter_order not in order:
                        match = False
                
                if match and filter_manufacturer:
                    if filter_manufacturer not in manufacturer:
                        match = False
                
                if match and filter_model:
                    if filter_model not in model:
                        match = False
                
                if match and filter_scenario:
                    if filter_scenario not in scenario:
                        match = False
                
                if match:
                    filtered_list.append(file_info)
            
            # 디버깅 로그
            try:
                self.log(f"[필터링] 전체: {len(self.all_saved_results)}개, 필터링 후: {len(filtered_list)}개")
                if filter_order or filter_manufacturer or filter_model or filter_scenario:
                    self.log(f"[필터링 조건] 차수: '{filter_order}', 제조사: '{filter_manufacturer}', 모델명: '{filter_model}', 시나리오: '{filter_scenario}'")
            except:
                pass
            
            # 필터링된 목록으로 트리 업데이트
            self._update_saved_results_tree(filtered_list)
        except Exception as e:
            import traceback
            error_msg = f"[필터링 오류] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass
    
    def clear_saved_results_filter(self):
        """저장된 결과 필터 초기화"""
        try:
            if hasattr(self, 'filter_order_combo'):
                self.filter_order_combo.setCurrentIndex(0)  # 빈 항목 선택
            if hasattr(self, 'filter_manufacturer_combo'):
                self.filter_manufacturer_combo.setCurrentIndex(0)
            if hasattr(self, 'filter_model_combo'):
                self.filter_model_combo.setCurrentIndex(0)
            if hasattr(self, 'filter_scenario_combo'):
                self.filter_scenario_combo.setCurrentIndex(0)
        except:
            pass
    
    def _update_saved_results_tree(self, file_list):
        """저장된 결과 트리 업데이트 (내부 메서드)"""
        try:
            if not hasattr(self, 'saved_results_tree') or not self.saved_results_tree:
                return
            
            self.saved_results_tree.clear()
            
            if not file_list:
                return
            
            # 파일명에서 차수, 제조사, 모델명 추출하여 그룹화
            groups = {}
            for file_info in file_list:
                order = file_info.get('order', '기타')
                manufacturer = file_info.get('manufacturer', '')
                model = file_info.get('model', '')
                
                # 그룹화 키 생성 (차수 + 제조사 + 모델명, 시나리오명은 제외)
                if manufacturer:
                    group_key = f"{order} {manufacturer} {model}".strip()
                else:
                    group_key = f"{order} {model}".strip()
                
                if order not in groups:
                    groups[order] = {}
                if group_key not in groups[order]:
                    groups[order][group_key] = []
                
                groups[order][group_key].append(file_info)
            
            # 트리 구성
            for order in sorted(groups.keys()):
                order_item = QTreeWidgetItem(self.saved_results_tree)
                order_item.setText(0, order)
                order_item.setExpanded(True)
                
                for group_key in sorted(groups[order].keys()):
                    model_item = QTreeWidgetItem(order_item)
                    model_item.setText(0, group_key)
                    model_item.setExpanded(True)
                    
                    # 해당 그룹의 파일들
                    for file_info in groups[order][group_key]:
                        result_item = QTreeWidgetItem(model_item)
                        result_item.setText(0, file_info['display_name'])
                        result_item.setData(0, Qt.UserRole, file_info['filepath'])
                        result_item.setData(0, Qt.UserRole + 1, file_info['data'])
        except Exception as e:
            import traceback
            error_msg = f"[트리 업데이트 오류] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass
    
    def on_saved_result_selected(self):
        """저장된 결과 선택 시"""
        try:
            selected = self.saved_results_tree.selectedItems()
            if not selected:
                return
            
            item = selected[0]
            data = item.data(0, Qt.UserRole + 1)
            if not data:
                return
            
            # 선택된 결과를 현재 결과 영역에 로드
            self.load_saved_result_to_current(data)
        except Exception as e:
            try:
                self.log(f"[저장된 결과 선택 오류] {e}")
            except:
                pass
    
    def on_saved_result_double_clicked(self, item, column):
        """저장된 결과 더블 클릭 시"""
        try:
            self.on_saved_result_selected()
        except Exception as e:
            try:
                self.log(f"[저장된 결과 더블 클릭 오류] {e}")
            except:
                pass
    
    def load_saved_result_to_current(self, data):
        """저장된 결과를 현재 결과 영역에 로드"""
        try:
            # 저장된 파일 경로와 소스 정보 저장
            self.saved_file_path = data.get('file_path')
            self.saved_source = data.get('source')
            
            # 아티팩트 데이터 로드
            self.artifact_data = {}
            artifact_names = {
                "1": "bootstat",
                "2-1": "recovery.log",
                "21": "recovery.log",
                "2-2": "last_log",
                "22": "last_log",
                "3": "suggestions.xml",
                "4": "persistent_properties",
                "5": "appops",
                "6": "wellbing",
                "7": "internal",
                "8": "eRR.p",
                "9": "ULR_PERSISTENT_PREFS.xml"
            }
            
            for artifact_id, artifact_data_list in data.get('artifact_data', {}).items():
                self.artifact_data[artifact_id] = []
                for data_item in artifact_data_list:
                    # 시간 문자열을 datetime으로 변환
                    time_value = None
                    if data_item.get('time'):
                        try:
                            time_value = datetime.fromisoformat(data_item['time'])
                        except:
                            try:
                                time_value = datetime.fromtimestamp(float(data_item['time']))
                            except:
                                pass
                    
                    self.artifact_data[artifact_id].append({
                        'name': data_item.get('name'),
                        'path': data_item.get('path'),
                        'time': time_value,
                        'message': data_item.get('message'),
                        'is_kst': data_item.get('is_kst', False),
                        'original_time': data_item.get('original_time')
                    })
                
                # 테이블 업데이트
                if artifact_id in self.artifact_tables:
                    self.update_table(artifact_id, self.artifact_data[artifact_id])
            
            # Update summary results
            self.update_summary_table()
            
            # 필터링 적용
            self.apply_artifact_filter()
            
            # 확정 시간 로드
            confirmed_time = data.get('confirmed_time')
            if confirmed_time:
                self.confirmed_time_value = confirmed_time
                self.confirmed_time_dt = self.parse_time_text(confirmed_time)
                self.update_confirmed_time_display()
                self.apply_confirmed_time_highlight()
            
            # Load deep search results
            if hasattr(self, 'deep_search_table') and self.deep_search_table:
                self.deep_search_table.setRowCount(0)
                for result in data.get('deep_search_results', []):
                    row = self.deep_search_table.rowCount()
                    self.deep_search_table.insertRow(row)
                    self.deep_search_table.setItem(row, 0, QTableWidgetItem(result.get('search_time', '')))
                    self.deep_search_table.setItem(row, 1, QTableWidgetItem(result.get('file_path', '')))
                    self.deep_search_table.setItem(row, 2, QTableWidgetItem(result.get('match_format', '')))
                    self.deep_search_table.setItem(row, 3, QTableWidgetItem(result.get('match_value', '')))
            
            # 탭 순서 재정렬
            self.reorder_tabs()
            
            # Set reset_instance (needed for deep search)
            source = data.get('source', 'zip')
            file_path = data.get('file_path', '')
            if file_path and source:
                # 모든 아티팩트 선택 (기본값)
                artifacts = ["1", "21", "22", "3", "4", "5", "6", "7", "8", "9"]
                try:
                    self.reset_instance = ResetClassGUI(source, artifacts, file_path, 
                                                        self.result_text, self)
                    # Collect file list from original analysis target path (for deep search)
                    if source == "1":  # ZIP
                        try:
                            # ZIP 파일 열기 (zip_ref는 나중에 사용할 수 있도록 유지)
                            zip_ref = zipfile.ZipFile(file_path, 'r')
                            self.reset_instance.file_list = zip_ref.namelist()
                            self.reset_instance.zipref = zip_ref
                            self.reset_instance.zipfile = file_path
                            self.log(f"[Deep Search Preparation] ZIP file list collected: {len(self.reset_instance.file_list)} files")
                        except Exception as e:
                            self.log(f"[경고] ZIP 파일 목록 수집 실패: {e}")
                    elif source == "3":  # Folder
                        try:
                            self.reset_instance.file_list = self.reset_instance.collect_folder_files(file_path)
                            self.reset_instance.base_path = file_path
                            self.log(f"[Deep Search Preparation] Folder file list collected: {len(self.reset_instance.file_list)} files")
                        except Exception as e:
                            self.log(f"[경고] 폴더 파일 목록 수집 실패: {e}")
                    # ADB mode uses get_adb_file_list() during deep search, so no separate handling needed
                except Exception as e:
                    self.log(f"[경고] reset_instance 생성 실패: {e}")
                    self.reset_instance = None
            
            # Enable deep search button (if data exists)
            if hasattr(self, 'btn_deep_search') and self.btn_deep_search:
                if self.artifact_data and any(self.artifact_data.values()):
                    self.btn_deep_search.setEnabled(True)
                else:
                    self.btn_deep_search.setEnabled(False)
            
            # 로그 메시지
            self.log(f"[저장된 결과 로드] {data.get('timestamp', 'N/A')} - {data.get('file_path', 'N/A')}")
        except Exception as e:
            import traceback
            error_msg = f"[저장된 결과 로드 오류] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass
        except Exception as e:
            import traceback
            error_msg = f"[저장된 결과 로드 오류] {str(e)}\n{traceback.format_exc()}"
            try:
                self.log(error_msg)
            except:
                pass
    
    def delete_saved_result(self):
        """선택된 저장 결과 삭제"""
        selected = self.saved_results_tree.selectedItems()
        if not selected:
            self.show_message("경고", "삭제할 결과를 선택하세요.")
            return
        
        item = selected[0]
        filepath = item.data(0, Qt.UserRole)
        
        if not filepath:
            self.show_message("경고", "유효하지 않은 선택입니다.")
            return
        
        reply = self.show_question("확인", "선택한 결과를 삭제하시겠습니까?")
        if reply == QMessageBox.Yes:
            try:
                os.remove(filepath)
                self.load_saved_results()  # 목록 새로고침
                self.show_message("완료", "삭제되었습니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"삭제 중 오류가 발생했습니다:\n{e}")


class ResetClassGUI:
    """GUI 버전의 ResetClass - print 대신 QTextEdit에 출력 및 표에 데이터 추가"""
    def __init__(self, choice, artifact_choices, file_path, output_widget, gui_instance=None):
        self.choice = choice
        self.artifact_choices = artifact_choices if isinstance(artifact_choices, list) else [artifact_choices]
        self.file_path = file_path
        self.output_widget = output_widget
        self.gui_instance = gui_instance  # FactoryResetGUI 인스턴스
        self.zipfile = None
        self.zipref = None
        self.base_path = None
        self.file_list = []
        self.adb_device_id = None  # 여러 디바이스가 있을 때 사용할 디바이스 ID
        self.last_abx_output = None
        
        # 로그 파일 설정
        self.log_file = None
        self.setup_logging()
    
    def setup_logging(self):
        """파일 로깅 설정"""
        try:
            log_dir = os.path.join(os.path.dirname(__file__), "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join(log_dir, f"analysis_{timestamp}.log")
            self.log_file = open(log_filename, 'w', encoding='utf-8')
            self.log_to_file(f"[로그 파일 생성] {log_filename}")
        except Exception as e:
            # 로그 파일 생성 실패해도 계속 진행
            pass
    
    def log_to_file(self, message):
        """파일에만 기록 (GUI 출력 없이)"""
        try:
            if self.log_file:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_file.write(f"[{timestamp}] {message}\n")
                self.log_file.flush()  # 즉시 디스크에 쓰기
        except Exception:
            pass
    
    def log(self, message):
        """출력 메서드 - QTextEdit에 텍스트 추가 및 파일에 기록"""
        try:
            # GUI에 출력
            if self.output_widget:
                self.output_widget.append(message)
            
            # 파일에 기록
            self.log_to_file(message)
        except Exception:
            # 로깅 실패해도 계속 진행
            pass
    
    def log_error(self, message, exception=None):
        """에러 로깅 (상세 정보 포함)"""
        error_msg = f"[ERROR] {message}"
        if exception:
            error_msg += f"\n{str(exception)}"
            error_msg += f"\n{traceback.format_exc()}"
        self.log(error_msg)
    
    def log_performance(self, operation, duration):
        """성능 로깅"""
        self.log(f"[PERFORMANCE] {operation}: {duration:.2f}초")
    
    def __del__(self):
        """소멸자 - 로그 파일 닫기"""
        try:
            if self.log_file:
                self.log_file.close()
        except:
            pass
    
    def run_analysis(self):
        """분석 실행"""
        start_time = datetime.now()
        self.log(f"[분석 시작] 모드: {self.choice}, 아티팩트: {self.artifact_choices}")
        
        try:
            if self.choice == "1":
                # ZIP 파일 모드
                if not self.file_path:
                    self.log("파일이 선택되지 않았습니다.")
                    return

                self.zipfile = self.file_path
                self.log(f"[#] zip 파일 경로 : {self.file_path}")

                try:
                    zip_start = datetime.now()
                    with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                        self.zipref = zip_ref
                        self.file_list = zip_ref.namelist()
                    zip_duration = (datetime.now() - zip_start).total_seconds()
                    self.log_performance("ZIP 파일 열기", zip_duration)
                    self.log(f"[ZIP 파일] 파일 수: {len(self.file_list)}")
                except Exception as e:
                    self.log_error("ZIP 파일 열기 실패", e)
                    return

                try:
                    user_id = self.get_user_path()
                    self.base_path = None
                    process_start = datetime.now()
                    self.process_artifacts_zip(user_id)
                    process_duration = (datetime.now() - process_start).total_seconds()
                    self.log_performance("아티팩트 처리", process_duration)
                except Exception as e:
                    self.log_error("아티팩트 처리 중 오류", e)
                    raise

            elif self.choice == "2":
                # ADB 모드
                self.log("[#] ADB 모드로 실행합니다.")

                try:
                    # ADB 연결 확인
                    if not self.check_adb_connection():
                        self.log("오류: ADB 연결을 확인할 수 없습니다.")
                        self.log("USB 디버깅이 활성화되어 있고 디바이스가 연결되어 있는지 확인하세요.")
                        return

                    # 루트 권한 확인
                    if not self.check_root_access():
                        self.log("경고: 루트 권한이 없습니다.")
                        self.log("일부 파일에 접근할 수 없을 수 있습니다.")
                        self.log("루트 권한이 필요한 경우 디바이스를 루팅하거나 su 명령을 허용하세요.")
                        # 경고만 표시하고 계속 진행

                    user_id = self.get_user_path()
                    process_start = datetime.now()
                    self.process_artifacts_adb(user_id)
                    process_duration = (datetime.now() - process_start).total_seconds()
                    self.log_performance("ADB 아티팩트 처리", process_duration)
                except Exception as e:
                    self.log_error("ADB 모드 처리 중 오류", e)
                    raise

            elif self.choice == "3":
                # Folder mode
                if not self.file_path:
                    self.log("Folder not selected.")
                    return

                try:
                    self.base_path = self.file_path
                    self.zipfile = None
                    self.zipref = None
                    self.log(f"[#] Folder path: {self.file_path}")
                    
                    collect_start = datetime.now()
                    self.file_list = self.collect_folder_files(self.file_path)
                    collect_duration = (datetime.now() - collect_start).total_seconds()
                    self.log_performance("Folder file collection", collect_duration)
                    self.log(f"[Folder] File count: {len(self.file_list)}")
            
                    user_id = self.get_user_path()
                    process_start = datetime.now()
                    self.process_artifacts_folder(user_id)
                    process_duration = (datetime.now() - process_start).total_seconds()
                    self.log_performance("폴더 아티팩트 처리", process_duration)
                except Exception as e:
                    self.log_error("폴더 모드 처리 중 오류", e)
                    raise
            else:
                self.log("Invalid choice. Exiting.")
        except Exception as e:
            self.log_error("분석 실행 중 치명적 오류", e)
            raise
        finally:
            total_duration = (datetime.now() - start_time).total_seconds()
            self.log_performance("전체 분석", total_duration)
            self.log(f"[분석 완료] 총 소요 시간: {total_duration:.2f}초")

    def should_process_artifact(self, artifact_id):
        """아티팩트를 처리해야 하는지 확인"""
        return "0" in self.artifact_choices or artifact_id in self.artifact_choices

    def process_artifacts_zip(self, user_id):
        """ZIP 모드에서 아티팩트 처리"""
        try:
            # artifact 1: bootstat
            if self.should_process_artifact("1"):
                target_file_in_bootstat = "Dump/data/misc/bootstat/factory_reset"
                target_file_in_bootstat_current = "Dump/data/misc/bootstat/factory_reset_current_time"
                matchtime = self.get_mod_time_from_zip(target_file_in_bootstat)
                matchtime_current = self.get_mod_time_from_zip(target_file_in_bootstat_current)
                self.log("******************************************")
                self.log(f"[1] [PATH : {target_file_in_bootstat}]")
                try:
                    if matchtime:
                        self.timestamp_process(matchtime, artifact_id="1", path=target_file_in_bootstat, name="factory_reset")
                    if matchtime_current:
                        self.timestamp_process(matchtime_current, artifact_id="1", path=target_file_in_bootstat_current, name="factory_reset_current_time")
                    if not matchtime and not matchtime_current and self.gui_instance:
                        self.gui_instance.add_artifact_data(
                            "1",
                            "factory_reset",
                            target_file_in_bootstat,
                            None,
                            "파일은 존재하나 시간 정보가 없습니다."
                        )
                except Exception as e:
                    self.log_error("factory_reset 처리 중 오류", e)
                self.log(f"factory_reset : {matchtime}")
                self.log(f"factory_reset_current_time : {matchtime_current}")
                self.log("******************************************\n")

            # artifact 2-1: recovery.log
            if self.should_process_artifact("21") or self.should_process_artifact("2-1"):
                try:
                    self.process_recovery_log_zip()
                except Exception as e:
                    self.log_error("recovery.log 처리 중 오류", e)

            # artifact 2-2: last_log
            if self.should_process_artifact("22") or self.should_process_artifact("2-2"):
                try:
                    self.process_last_log_zip()
                except Exception as e:
                    self.log_error("last_log 처리 중 오류", e)

            # artifact 3: suggestions.xml
            if self.should_process_artifact("3"):
                try:
                    self.process_suggestions_zip(user_id)
                except Exception as e:
                    self.log_error("suggestions.xml 처리 중 오류", e)

            # artifact 4: persistent_properties
            if self.should_process_artifact("4"):
                try:
                    self.process_persistent_properties_zip()
                except Exception as e:
                    self.log_error("persistent_properties 처리 중 오류", e)

            # artifact 5: appops
            if self.should_process_artifact("5"):
                try:
                    self.process_appops_zip()
                except Exception as e:
                    self.log_error("appops 처리 중 오류", e)

            # artifact 6: wellbing
            if self.should_process_artifact("6"):
                try:
                    self.process_wellbing_zip()
                except Exception as e:
                    self.log_error("wellbing 처리 중 오류", e)

            # artifact 7: internal
            if self.should_process_artifact("7"):
                try:
                    self.process_internal_zip(user_id)
                except Exception as e:
                    self.log_error("internal 처리 중 오류", e)

            # artifact 8: eRR.p
            if self.should_process_artifact("8"):
                try:
                    self.process_err_zip()
                except Exception as e:
                    self.log_error("eRR.p 처리 중 오류", e)
            
            # artifact 9: ULR_PERSISTENT_PREFS.xml
            if self.should_process_artifact("9"):
                try:
                    self.process_ulr_zip(user_id)
                except Exception as e:
                    self.log_error("ULR_PERSISTENT_PREFS.xml 처리 중 오류", e)
        except Exception as e:
            self.log_error("ZIP 아티팩트 처리 중 치명적 오류", e)
            raise

    def process_artifacts_folder(self, user_id):
        """폴더 모드에서 아티팩트 처리 (ZIP과 동일한 로직)"""
        # artifact 1: bootstat
        if self.should_process_artifact("1"):
            target_file_in_bootstat = "Dump/data/misc/bootstat/factory_reset"
            target_file_in_bootstat_current = "Dump/data/misc/bootstat/factory_reset_current_time"
            matchtime = self.get_mod_time_from_zip(target_file_in_bootstat)
            matchtime_current = self.get_mod_time_from_zip(target_file_in_bootstat_current)
            self.log("******************************************")
            self.log(f"[1] [PATH : {target_file_in_bootstat}]")
            try:
                if matchtime:
                    self.timestamp_process(matchtime, artifact_id="1", path=target_file_in_bootstat, name="factory_reset")
                if matchtime_current:
                    self.timestamp_process(matchtime_current, artifact_id="1", path=target_file_in_bootstat_current, name="factory_reset_current_time")
                if not matchtime and not matchtime_current and self.gui_instance:
                    self.gui_instance.add_artifact_data(
                        "1",
                        "factory_reset",
                        target_file_in_bootstat,
                        None,
                        "파일은 존재하나 시간 정보가 없습니다."
                    )
            except Exception as e:
                self.log(f"factory_reset : {matchtime}")
                self.log(f"factory_reset_current_time : {matchtime_current}")
            self.log("******************************************\n")

        # artifact 2-1: recovery.log
        if self.should_process_artifact("21") or self.should_process_artifact("2-1"):
            self.process_recovery_log_folder()

        # artifact 2-2: last_log
        if self.should_process_artifact("22") or self.should_process_artifact("2-2"):
            self.process_last_log_folder()

        # artifact 3: suggestions.xml
        if self.should_process_artifact("3"):
            self.process_suggestions_folder(user_id)

        # artifact 4: persistent_properties
        if self.should_process_artifact("4"):
            self.process_persistent_properties_folder()

        # artifact 5: appops
        if self.should_process_artifact("5"):
            self.process_appops_folder()

        # artifact 6: wellbing
        if self.should_process_artifact("6"):
            self.process_wellbing_folder()

        # artifact 7: internal
        if self.should_process_artifact("7"):
            self.process_internal_folder(user_id)

        # artifact 8: eRR.p
        if self.should_process_artifact("8"):
            self.process_err_folder()
        
        # artifact 9: ULR_PERSISTENT_PREFS.xml
        if self.should_process_artifact("9"):
            self.process_ulr_folder(user_id)

    def process_artifacts_adb(self, user_id):
        """ADB 모드에서 아티팩트 처리"""
        # ADB 모드의 아티팩트 처리 로직 (기존 코드의 choice == "2" 부분)
        # artifact 2-1: recovery.log
        if self.should_process_artifact("21") or self.should_process_artifact("2-1"):
            self.process_recovery_log_adb()

        # artifact 2-2: last_log
        if self.should_process_artifact("22") or self.should_process_artifact("2-2"):
            self.process_last_log_adb()

        # artifact 3: suggestions.xml
        if self.should_process_artifact("3"):
            self.process_suggestions_adb(user_id)

        # artifact 4: persistent_properties
        if self.should_process_artifact("4"):
            self.process_persistent_properties_adb()

        # artifact 5: appops
        if self.should_process_artifact("5"):
            self.process_appops_adb()

        # artifact 6: wellbing
        if self.should_process_artifact("6"):
            self.process_wellbing_adb()

        # artifact 7: internal
        if self.should_process_artifact("7"):
            self.process_internal_adb(user_id)
 
        # artifact 8: eRR.p
        if self.should_process_artifact("8"):
            self.process_err_adb()

    def _parse_recovery_timeline(self, content, file_path, artifact_id):
        """recovery.log/last_log에서 기준 시간과 초기화 관련 로그 시간 계산"""
        if not content:
            return False
        
        # 1. get_system_time 패턴 찾기 (기준 시간)
        base_time = None
        base_rel = None
        
        # 패턴 1: get_system_time=2024-11-20-08:42:11 형식
        pattern1 = r'get_system_time=(\d{4}-\d{2}-\d{2})-(\d{2}:\d{2}:\d{2})'
        # 패턴 2: [상대시간] ... get_system_time= 형식
        pattern2 = r'\[\s*(\d+\.\d+)\]\s+.*get_system_time=(\d{4}-\d{2}-\d{2})-(\d{2}:\d{2}:\d{2})'
        
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # 패턴 2 시도 (상대 시간 포함)
            m2 = re.search(pattern2, line)
            if m2:
                base_rel = float(m2.group(1))
                try:
                    base_time = datetime.strptime(f"{m2.group(2)} {m2.group(3)}", "%Y-%m-%d %H:%M:%S")
                    self.log(f"[기준 시간 발견] 라인 {i+1}: get_system_time={base_time} (상대시간: {base_rel}초)")
                    break
                except ValueError:
                    continue
            
            # 패턴 1 시도 (상대 시간 없음)
            m1 = re.search(pattern1, line)
            if m1 and base_time is None:
                try:
                    base_time = datetime.strptime(f"{m1.group(1)} {m1.group(2)}", "%Y-%m-%d %H:%M:%S")
                    self.log(f"[기준 시간 발견] 라인 {i+1}: get_system_time={base_time}")
                except ValueError:
                    continue
        
        if base_time is None:
            return False
        
        # 2. 초기화 관련 로그 찾기
        wipe_keywords = [
            (r'--\s*Wiping\s+data', "초기화 시작"),
            (r'Data\s+wipe\s+complete', "초기화 완료"),
            (r'Formatting\s+/data', "데이터 포맷팅 시작"),
            (r'Info:\s*format\s+successful', "포맷 완료"),
        ]
        
        found_events = []
        for i, line in enumerate(lines):
            # 상대 시간 추출 시도
            rel_match = re.match(r'\[\s*(\d+\.\d+)\]\s+(.*)$', line)
            if rel_match:
                rel_time = float(rel_match.group(1))
                msg = rel_match.group(2)
                
                for pattern, event_name in wipe_keywords:
                    if re.search(pattern, msg, re.IGNORECASE):
                        if base_rel is not None:
                            # 기준 상대 시간이 있으면 차이 계산
                            abs_time = base_time + timedelta(seconds=(rel_time - base_rel))
                        else:
                            # 기준 상대 시간이 없으면 기준 시간 그대로 사용 (정확도 낮음)
                            abs_time = base_time
                        
                        found_events.append({
                            'line': i + 1,
                            'rel_time': rel_time,
                            'abs_time': abs_time,
                            'event': event_name,
                            'message': msg.strip()
                        })
                        self.log(f"[초기화 이벤트] 라인 {i+1} (상대: {rel_time:.6f}초): {event_name} = {abs_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                        break
        
        # 3. 결과를 GUI에 추가
        if found_events and self.gui_instance:
            import calendar
            # get_system_time 패턴은 KST 기준 (Xiaomi 타임라인과 동일)
            # recovery.log의 "Starting recovery" 패턴은 UTC 0 기준
            is_kst_for_timeline = (artifact_id == "22")  # last_log는 KST, recovery.log는 UTC
            
            for event in found_events:
                if is_kst_for_timeline:
                    # last_log의 get_system_time은 KST 기준이므로 그대로 사용
                    # KST datetime을 UTC로 변환하려면 9시간 빼기
                    utc_time = event['abs_time'] - timedelta(hours=9)
                    utc_timestamp = calendar.timegm(utc_time.utctimetuple())
                else:
                    # recovery.log는 UTC 0 기준
                    utc_timestamp = calendar.timegm(event['abs_time'].utctimetuple())
                
                self.timestamp_process(
                    utc_timestamp,
                    artifact_id=artifact_id,
                    path=file_path,
                    name=f"recovery.log ({event['event']})" if artifact_id == "21" else f"last_log ({event['event']})",
                    original_time=f"라인 {event['line']}: {event['message']}",
                    is_kst=is_kst_for_timeline
                )
        
        return len(found_events) > 0
    
    def _parse_recovery_log_content(self, content, file_path):
        """recovery.log 내용 파싱 (공통 로직) - UTC 0 기준"""
        if not content:
            return False
        
        success = False
        
        # 1. Starting recovery 패턴 (기본)
        pattern = r'(?:I:)?Starting recovery\s*\(pid\s+\d+\)\s+on\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
        matches = re.findall(pattern, content)
        if matches:
            time_str = matches[0]
            try:
                # recovery.log는 UTC 0 기준이므로 naive datetime을 UTC로 간주
                dt_naive = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y")
                # UTC 기준으로 epoch 계산: calendar.timegm() 사용 (UTC 기준)
                import calendar
                utc_timestamp = calendar.timegm(dt_naive.utctimetuple())
                
                self.log("******************************************")
                self.log(f"[2-1] [PATH : {file_path}]")
                self.log(f"recovery.log UTC 시간: {dt_naive} (UTC 0 기준, epoch: {utc_timestamp})")
                self.timestamp_process(utc_timestamp, artifact_id="21", path=file_path, name="recovery.log", original_time=time_str)
                self.log("******************************************\n")
                success = True
            except ValueError as e:
                self.log(f"[2-1] 날짜 파싱 오류: {e}")
        else:
            self.log_parse_failure(file_path, "recovery.log 패턴 불일치", content)
        
        # 2. 타임라인 분석 (초기화 시간 계산)
        if self._parse_recovery_timeline(content, file_path, "21"):
            success = True
        
        return success
    
    def _read_file_by_mode(self, file_path):
        """모드에 따라 파일 읽기"""
        if self.choice == "1":  # ZIP
            if self.search_zip(file_path):
                return self.read_file(file_path)
        elif self.choice == "2":  # ADB
            if self.adb_file_exists(file_path):
                return self.adb_read_file(file_path)
        elif self.choice == "3":  # Folder
            if self.search_zip(file_path):  # folder도 search_zip 사용
                return self.read_file(file_path)
        return None
    
    def _read_file_bytes_by_mode(self, file_path):
        """모드에 따라 바이너리 파일 읽기"""
        if self.choice == "1":  # ZIP
            if self.search_zip(file_path):
                return self.read_file_bytes(file_path)
        elif self.choice == "2":  # ADB
            if self.adb_file_exists(file_path):
                return self.adb_read_file_bytes(file_path)
        elif self.choice == "3":  # Folder
            if self.search_zip(file_path):
                return self.read_file_bytes(file_path)
        return None
    
    def _file_exists_by_mode(self, file_path):
        """모드에 따라 파일 존재 확인"""
        if self.choice == "1":  # ZIP
            return self.search_zip(file_path)
        elif self.choice == "2":  # ADB
            return self.adb_file_exists(file_path)
        elif self.choice == "3":  # Folder
            return self.search_zip(file_path)  # folder도 search_zip 사용
        return False
    
    def process_recovery_log(self):
        """recovery.log 처리 (모든 모드 공통)"""
        recovery_success = False
        found_path = None
        
        # 모드에 따라 경로 설정
        if self.choice == "2":  # ADB
                targets = [
                "/data/log/Recovery.log",
                "/data/log/recovery.log",
                "/cache/recovery/log",
            ]
        else:  # ZIP or Folder
            targets = [
                "Dump/data/log/Recovery.log",
                "Dump/data/log/recovery.log",
                "Dump/cache/recovery/log",
            ]
        
        for target_file in targets:
            if self._file_exists_by_mode(target_file):
                found_path = target_file
                try:
                    content = self._read_file_by_mode(target_file)
                    if self._parse_recovery_log_content(content, target_file):
                        recovery_success = True
                        break
                except Exception as e:
                    self.log(f"[2-1] recovery.log 처리 중 오류: {e}")
        
        if not recovery_success:
            self.log("******************************************")
            self.log("[2-1] [recovery.log 파일이 존재하지 않거나 시간 정보가 없습니다.]")
            self.log("******************************************\n")
            # 시간이 없어도 표에 추가
            if self.gui_instance:
                self.gui_instance.add_artifact_data(
                    "21",
                    "recovery.log",
                    found_path or "",
                    None,
                    "파일이 존재하지 않거나 시간 정보가 없습니다."
                )
    
    def process_recovery_log_zip(self):
        """ZIP 모드용 (하위 호환성)"""
        self.process_recovery_log()
    
    def process_recovery_log_folder(self):
        """Folder 모드용 (하위 호환성)"""
        self.process_recovery_log()
    
    def process_recovery_log_adb(self):
        """ADB 모드용 (하위 호환성)"""
        self.process_recovery_log()
    
    def _parse_last_log_content(self, content, raw_bytes, file_path):
        """last_log 내용 파싱 (공통 로직) - UTC 0 기준"""
        success = False
        
        # recovery.log 패턴 시도
        if content:
            pattern = r'(?:I:)?Starting recovery\s*\(pid\s+\d+\)\s+on\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
            matches = re.findall(pattern, content)
            if matches:
                time_str = matches[0]
                try:
                    # last_log도 UTC 0 기준이므로 naive datetime을 UTC로 간주
                    dt_naive = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y")
                    # UTC 기준으로 epoch 계산: calendar.timegm() 사용 (UTC 기준)
                    import calendar
                    utc_timestamp = calendar.timegm(dt_naive.utctimetuple())
                    
                    self.log("******************************************")
                    self.log(f"[2-2] [PATH : {file_path}]")
                    self.log(f"last_log UTC 시간: {dt_naive} (UTC 0 기준, epoch: {utc_timestamp})")
                    self.timestamp_process(utc_timestamp, artifact_id="22", path=file_path, name="last_log", original_time=time_str)
                    self.log("******************************************\n")
                    success = True
                except ValueError as e:
                    self.log(f"[2-2] 날짜 파싱 오류: {e}")
        else:
            self.log_parse_failure(file_path, "last_log 패턴 불일치", content)
        
        # 타임라인 분석 (초기화 시간 계산) - get_system_time 패턴 사용
        timeline_success = False
        if content and self._parse_recovery_timeline(content, file_path, "22"):
            timeline_success = True
            success = True
        
        # Xiaomi 타임라인 시도 (타임라인 분석이 실패한 경우에만)
        if not timeline_success and raw_bytes:
            text = raw_bytes.decode("utf-8", errors="ignore")
            parsed = self.parse_xiaomi_last_log_timeline(text)
            if parsed:
                self.log("******************************************")
                self.log(f"[2-2] [Xiaomi last_log 타임라인] [PATH : {file_path}]")
                self.log(f"BASE get_system_time: {parsed['base_dt'].strftime('%Y-%m-%d %H:%M:%S')} KST (rel={parsed['base_rel']:.6f}s)")
                
                # base 시간 추가 (KST를 UTC로 변환하여 저장)
                if self.gui_instance:
                    import calendar
                    # KST를 UTC로 변환하여 저장
                    utc_base = parsed['base_dt'] - timedelta(hours=9)
                    utc_timestamp = calendar.timegm(utc_base.utctimetuple())
                    self.timestamp_process(
                        utc_timestamp,
                        artifact_id="22",
                        path=file_path,
                        name="last_log (Xiaomi base)",
                        original_time=f"get_system_time={parsed['base_dt'].strftime('%Y-%m-%d %H:%M:%S')}",
                        is_kst=True
                    )
                
                # 타임라인 이벤트들도 추가 (초기화 관련만)
                if self.gui_instance:
                    import calendar
                    for abs_str, rel, msg in parsed["timeline"]:
                        # abs_str에서 시간 추출 (KST)
                        try:
                            abs_dt_str = abs_str.replace(" KST", "").strip()
                            abs_dt = datetime.strptime(abs_dt_str, "%Y-%m-%d %H:%M:%S.%f")
                            # KST를 UTC로 변환
                            utc_dt = abs_dt - timedelta(hours=9)
                            utc_timestamp = calendar.timegm(utc_dt.utctimetuple())
                            
                            # 초기화 관련 이벤트만 추가
                            if any(k in msg for k in ["-- Wiping data", "Data wipe complete", "Formatting /data", "Info: format successful"]):
                                event_name = "초기화 시작" if "Wiping" in msg else "초기화 완료" if "complete" in msg or "complete" in msg.lower() else "포맷팅"
                                self.timestamp_process(
                                    utc_timestamp,
                                    artifact_id="22",
                                    path=file_path,
                                    name=f"last_log ({event_name})",
                                    original_time=f"라인: {msg}",
                                    is_kst=True
                                )
                        except Exception as e:
                            self.log(f"[Xiaomi 타임라인 파싱 오류] {abs_str}: {e}")
                        
                        self.log(f"{abs_str}  (rel={rel:9.6f}s)  {msg}")
                self.log("******************************************\n")
                success = True
        
        return success
    
    def process_last_log(self):
        """last_log 처리 (모든 모드 공통)"""
        last_log_success = False
        found_path = None
        
        # 모드에 따라 경로 설정
        if self.choice == "2":  # ADB
            targets = ["/cache/recovery/last_log"]
        else:  # ZIP or Folder
                targets = [
                "Dump/cache/recovery/last_log",
                    "Dump/mnt/rescue/recovery/last_log",
                    "Dump/mnt/rescue/recovery/last_log.1",
                    "Dump/mnt/rescue/recovery/last_kmsg",
                    "Dump/mnt/rescue/recovery/last_kmsg.1",
                ]
        
        for target_file in targets:
            if self._file_exists_by_mode(target_file):
                found_path = target_file
                try:
                    content = self._read_file_by_mode(target_file)
                    raw_bytes = self._read_file_bytes_by_mode(target_file)
                    if self._parse_last_log_content(content, raw_bytes, target_file):
                        last_log_success = True
                        break
                except Exception as e:
                    self.log(f"[2-2] last_log 처리 중 오류: {e}")
        
        if not last_log_success:
            self.log("******************************************")
            self.log("[2-2] [last_log 파일이 존재하지 않거나 시간 정보가 없습니다.]")
            self.log("******************************************\n")
            if self.gui_instance:
                self.gui_instance.add_artifact_data(
                    "22",
                    "last_log",
                    found_path or "",
                    None,
                    "파일이 존재하지 않거나 시간 정보가 없습니다."
                )
    
    def process_last_log_zip(self):
        """ZIP 모드용 (하위 호환성)"""
        self.process_last_log()
    
    def process_last_log_folder(self):
        """Folder 모드용 (하위 호환성)"""
        self.process_last_log()
    
    def process_last_log_adb(self):
        """ADB 모드용 (하위 호환성)"""
        self.process_last_log()
    
    def _parse_suggestions_content(self, content, file_path):
        """suggestions.xml 내용 파싱 (공통 로직)"""
        if not content:
            return False
        
        pattern = r'<long name="com\.android\.settings\.suggested\.category\.DEFERRED_SETUP_setup_time"\s+value="(\d+)"'
        matches = re.findall(pattern, content)
        if matches:
            self.log("******************************************")
            self.log(f"[3] [PATH : {file_path}]")
            self.timestamp_process(matches[0], artifact_id="3", path=file_path, name="suggestions.xml")
            self.log("******************************************\n")
            return True
        else:
            self.log_parse_failure(file_path, "suggestions.xml 값 없음", content)
        return False
    
    def process_suggestions(self, user_id):
        """suggestions.xml 처리 (모든 모드 공통)"""
        suggestion_success = False
        found_path = None
        pattern = r'<long name="com\.android\.settings\.suggested\.category\.DEFERRED_SETUP_setup_time"\s+value="(\d+)"'
        
        # 모드에 따라 경로 설정
        if self.choice == "2":  # ADB
            targets = [
                "/data/data/com.android.settings.intelligence/shared_prefs/suggestions.xml",
                f"/data/user/{user_id}/com.google.android.settings.intelligence/shared_prefs/suggestions.xml",
                f"/data/user_de/{user_id}/com.google.android.settings.intelligence/shared_prefs/suggestions.xml"
            ]
        else:  # ZIP or Folder
            targets = [
                "Dump/data/data/com.android.settings.intelligence/shared_prefs/suggestions.xml",
                f"Dump/data/user/{user_id}/com.google.android.settings.intelligence/shared_prefs/suggestions.xml",
                f"Dump/data/user_de/{user_id}/com.google.android.settings.intelligence/shared_prefs/suggestions.xml"
            ]
        
        for target_file in targets:
            if self._file_exists_by_mode(target_file):
                found_path = target_file
                try:
                    if self.choice in ["1", "3"]:  # ZIP or Folder
                        extracted, matches = self.search_timestamp_in_property(target_file, pattern)
                        if extracted is not None and matches:
                            self.log("******************************************")
                            self.log(f"[3] [PATH : {target_file}]")
                            self.timestamp_process(matches[0], artifact_id="3", path=target_file, name="suggestions.xml")
                            self.log("******************************************\n")
                            suggestion_success = True
                            break
                    else:  # ADB
                        content = self._read_file_by_mode(target_file)
                        if self._parse_suggestions_content(content, target_file):
                            suggestion_success = True
                            break
                except Exception as e:
                    self.log(f"[3] suggestions.xml 처리 중 오류: {e}")
        
        if not suggestion_success:
            self.log("******************************************")
            self.log("[3] [suggestions.xml 파일이 존재하지 않거나 값이 없습니다.]")
            self.log("******************************************\n")
            if self.gui_instance:
                self.gui_instance.add_artifact_data(
                    "3",
                    "suggestions.xml",
                    found_path or "",
                    None,
                    "파일이 존재하지 않거나 값이 없습니다."
                )
    
    def process_suggestions_zip(self, user_id):
        """ZIP 모드용 (하위 호환성)"""
        self.process_suggestions(user_id)
    
    def process_suggestions_folder(self, user_id):
        """Folder 모드용 (하위 호환성)"""
        self.process_suggestions(user_id)
    
    def process_suggestions_adb(self, user_id):
        """ADB 모드용 (하위 호환성)"""
        self.process_suggestions(user_id)
    
    def _parse_persistent_properties_content(self, content, file_path):
        """persistent_properties 내용 파싱 (공통 로직)"""
        if not content:
            return False
        
        keyword = "reboot,factory_reset"
        # 패턴: reboot,factory_reset 뒤에 쉼표나 공백/콜론/등호가 오고 10자리 이상 숫자
        # 예: persist.sys.boot.reason.history.reboot,factory_reset,1689128778
        # 쉼표로 바로 연결된 경우도 처리: reboot,factory_reset,1689128778
        # 개행 문자도 고려하여 여러 패턴 시도
        
        # 패턴 1: 쉼표 바로 뒤에 숫자 (가장 일반적)
        pattern1 = rf"{re.escape(keyword)},(\d{{10,}})"
        matches = re.findall(pattern1, content)
        
        # 패턴 2: 공백/개행 후 숫자
        if not matches:
            pattern2 = rf"{re.escape(keyword)}[\s,:=]+(\d{{10,}})"
            matches = re.findall(pattern2, content, re.MULTILINE)
        
        # 패턴 3: 더 유연한 패턴 (개행 포함)
        if not matches:
            pattern3 = rf"{re.escape(keyword)}[,\s:=]+(\d{{10,}})"
            matches = re.findall(pattern3, content, re.DOTALL)
        
        if matches:
            # 전체 매칭 문자열 찾기 (원본 시간 저장용)
            full_pattern = rf"{re.escape(keyword)}[,\s:=]+(\d{{10,}})"
            full_match = re.search(full_pattern, content, re.MULTILINE | re.DOTALL)
            if full_match:
                original_time_str = full_match.group(0)
            else:
                original_time_str = f"{keyword},{matches[0]}"
            
            self.log("******************************************")
            self.log(f"[4] [PATH : {file_path}]")
            self.log(f"[4] [매칭된 값] {matches[0]}")
            self.timestamp_process(matches[0], artifact_id="4", path=file_path, name="persistent_properties", original_time=original_time_str)
            self.log("******************************************\n")
            return True
        else:
            # 디버깅: 내용 일부 출력
            content_preview = content[:500] if len(content) > 500 else content
            self.log("******************************************")
            self.log(f"[4] [PATH : {file_path}]")
            self.log("[4] [값이 존재하지 않습니다.]")
            self.log(f"[4] [디버깅] 내용 미리보기:\n{content_preview}")
            self.log("******************************************\n")
            self.log_parse_failure(file_path, "persistent_properties 값 없음", content)
            if self.gui_instance:
                self.gui_instance.add_artifact_data("4", "persistent_properties", file_path, None, "값이 존재하지 않습니다.")
        return False
    
    def process_persistent_properties(self):
        """persistent_properties 처리 (모든 모드 공통)"""
        if self.choice == "2":  # ADB
            target_file = "/data/property/persistent_properties"
        else:  # ZIP or Folder
                target_file = "Dump/data/property/persistent_properties"
        
        if self._file_exists_by_mode(target_file):
            try:
                if self.choice in ["1", "3"]:  # ZIP or Folder
                    keyword = "reboot,factory_reset"
                    # 패턴: reboot,factory_reset 뒤에 쉼표나 공백/콜론/등호가 오고 10자리 숫자
                    # 예: persist.sys.boot.reason.history.reboot,factory_reset,1689128778
                    # 쉼표로 바로 연결된 경우도 처리: reboot,factory_reset,1689128778
                    # 패턴 수정: 쉼표 바로 뒤에 숫자가 오는 경우도 처리, 10자리 이상 숫자 허용
                    pattern = rf"{re.escape(keyword)}[,\s:=]+(\d{{10,}})"
                    resulttime, matches = self.search_timestamp_in_property(target_file, pattern)
                    if resulttime is not None and matches:
                        # 전체 매칭 문자열 찾기 (원본 시간 저장용)
                        content = self._read_file_by_mode(target_file)
                        if content:
                            full_pattern = rf"{re.escape(keyword)}[,\s:=]+(\d{{10,}})"
                            full_match = re.search(full_pattern, content, re.MULTILINE | re.DOTALL)
                            original_time_str = full_match.group(0) if full_match else matches[0]
                        else:
                            original_time_str = matches[0]
                        
                        self.log("******************************************")
                        self.log(f"[4] [PATH : {target_file}]")
                        self.timestamp_process(matches[0], artifact_id="4", path=target_file, name="persistent_properties", original_time=original_time_str)
                        self.log("******************************************\n")
                    else:
                        content = self._read_file_by_mode(target_file)
                        self._parse_persistent_properties_content(content, target_file)
                else:  # ADB
                    content = self._read_file_by_mode(target_file)
                    self._parse_persistent_properties_content(content, target_file)
            except Exception as e:
                self.log(f"Persistent properties 처리 중 오류: {e}")
                import traceback
                self.log(traceback.format_exc())
        else:
            if self.choice == "2":
                self.log(f"{target_file} does not exist on device.")
            else:
                self.log(f"{target_file}이(가) ZIP 파일에 존재하지 않습니다.")
            if self.gui_instance:
                self.gui_instance.add_artifact_data("4", "persistent_properties", target_file, None, "파일이 존재하지 않습니다.")
    
    def process_persistent_properties_zip(self):
        """ZIP 모드용 (하위 호환성)"""
        self.process_persistent_properties()
    
    def process_persistent_properties_folder(self):
        """Folder 모드용 (하위 호환성)"""
        self.process_persistent_properties()
    
    def process_persistent_properties_adb(self):
        """ADB 모드용 (하위 호환성)"""
        self.process_persistent_properties()
    
    def process_appops(self):
        """appops.xml 처리 (모든 모드 공통)"""
        if self.choice == "2":  # ADB
            target_file = "/data/system/appops.xml"
        else:  # ZIP or Folder
                target_file = "Dump/data/system/appops.xml"
        
        self.log("******************************************")
        if self._file_exists_by_mode(target_file):
            matchtimeonly = self.extract_from_binary_xml(target_file, adb_mode=(self.choice == "2"))
            if matchtimeonly:
                self.log(f"[5] [PATH : {target_file}]")
                self.timestamp_process(matchtimeonly[0], artifact_id="5", path=target_file, name="appops.xml")
            else:
                self.log("[5] [no timestamp in appops.xml]")
                content = self._read_file_by_mode(target_file)
                self.log_parse_failure(target_file, "appops.xml 타임스탬프 없음", content)
                if self.gui_instance:
                    self.gui_instance.add_artifact_data("5", "appops.xml", target_file, None, "타임스탬프가 없습니다.")
        else:
            if self.choice == "2":
                self.log(f"{target_file} does not exist on device.")
            else:
                self.log(f"{target_file}이(가) ZIP 파일에 존재하지 않습니다.")
            if self.gui_instance:
                self.gui_instance.add_artifact_data("5", "appops.xml", target_file, None, "파일이 존재하지 않습니다.")
        self.log("******************************************\n")
    
    def process_appops_zip(self):
        """ZIP 모드용 (하위 호환성)"""
        self.process_appops()
    
    def process_appops_folder(self):
        """Folder 모드용 (하위 호환성)"""
        self.process_appops()
    
    def process_appops_adb(self):
        """ADB 모드용 (하위 호환성)"""
        self.process_appops()
    
    def process_wellbing_zip(self):
                queryforpixel = """
                    SELECT events._id,
                           datetime(events.timestamp/1000, 'UNIXEPOCH') as timestamps,
                           packages.package_name, events.type,
                           CASE
                               when events.type=1 THEN 'ACTIVITY_RESUMED'
                               when events.type=2 THEN 'ACTIVITY_PAUSED'
                               when events.type=12 THEN 'NOTIFICATION'
                               when events.type=18 THEN 'KEYGUARD_HIDDEN || DEVICE UNLOCK'
                               when events.type=19 THEN 'FOREGROUND_SERVICE START'
                               when events.type=20 THEN 'FOREGROUND_SERVICE_STOP'
                               when events.type=23 THEN 'ACTIVITY_STOPPED'
                               when events.type=26 THEN 'DEVICE_SHUTDOWN'
                               when events.type=27 THEN 'DEVICE_STARTUP'
                               else events.type
                           END as eventtype
                    FROM events
                    INNER JOIN packages ON events.package_id=packages._id
                    ORDER by timestamps
                """
                queryforgalaxy = """
                    SELECT usageEvents.eventId,
                           datetime(usageEvents.timeStamp/1000, 'UNIXEPOCH') as timestamp,
                           foundPackages.name, usageEvents.eventType,
                           CASE
                               when usageEvents.eventType=1 THEN 'ACTIVITY_RESUMED'
                               when usageEvents.eventType=2 THEN 'ACTIVITY_PAUSED'
                               when usageEvents.eventType=5 THEN 'CONFIGURATION_CHANGE'
                               when usageEvents.eventType=7 THEN 'USER_INTERACTION'
                               when usageEvents.eventType=10 THEN 'NOTIFICATION PANEL'
                               when usageEvents.eventType=11 THEN 'STANDBY_BUCKET_CHANGED'
                               when usageEvents.eventType=12 THEN 'NOTIFICATION'
                               when usageEvents.eventType=15 THEN 'SCREEN_INTERACTIVE (Screen on for full user interaction)'
                               when usageEvents.eventType=16 THEN 'SCREEN_NON_INTERACTIVE (Screen on in Non-interactive state or completely turned off)'
                               when usageEvents.eventType=17 THEN 'KEYGUARD_SHOWN || POSSIBLE DEVICE LOCK'
                               when usageEvents.eventType=18 THEN 'KEYGUARD_HIDDEN || DEVICE UNLOCK'
                               when usageEvents.eventType=19 THEN 'FOREGROUND_SERVICE START'
                               when usageEvents.eventType=20 THEN 'FOREGROUND_SERVICE_STOP'
                               when usageEvents.eventType=23 THEN 'ACTIVITY_STOPPED'
                               when usageEvents.eventType=26 THEN 'DEVICE_SHUTDOWN'
                               when usageEvents.eventType=27 THEN 'DEVICE_STARTUP'
                               else usageEvents.eventType
                           END as eventTypeDescription
                    FROM usageEvents
                    INNER JOIN foundPackages ON usageEvents.pkgId=foundPackages.pkgId
                    ORDER BY timestamp
                """
                wellbing_success = False
                for target_file in ["Dump/data/data/com.google.android.apps.wellbeing/databases/app_usage",
                                    "Dump/data/data/com.samsung.android.forest/databases/dwbCommon.db"]:
                    if self.search_zip(target_file):
                        dbresult = self.execute_wellbing_query(
                            target_file,
                            queryforpixel if "wellbeing" in target_file else queryforgalaxy
                        )
                        self.log("******************************************")
                        self.log(f"[6] [PATH : {target_file}]")
                        self.log(str(dbresult))
                        self.log("******************************************\n")
                        wellbing_success = True
                        if self.gui_instance and (dbresult is None or str(dbresult).strip() == "" or str(dbresult).strip() == "None"):
                            self.gui_instance.add_artifact_data("6", "wellbing", target_file, None, "시간 정보가 없습니다.")
                        break
                if not wellbing_success:
                    self.log("There is no wellbing file in phone")
                    # ????????????? ???
                    if self.gui_instance:
                        self.gui_instance.add_artifact_data("6", "wellbing", "", None, "파일이 존재하지 않습니다.")

    def process_wellbing_folder(self):
        self.process_wellbing_zip()  # 동일한 로직
    
    def process_wellbing_adb(self):
                queryforpixel = """
                    SELECT events._id,
                           datetime(events.timestamp/1000, 'UNIXEPOCH') as timestamps,
                           packages.package_name, events.type,
                           CASE
                               when events.type=1 THEN 'ACTIVITY_RESUMED'
                               when events.type=2 THEN 'ACTIVITY_PAUSED'
                               when events.type=12 THEN 'NOTIFICATION'
                               when events.type=18 THEN 'KEYGUARD_HIDDEN || DEVICE UNLOCK'
                               when events.type=19 THEN 'FOREGROUND_SERVICE START'
                               when events.type=20 THEN 'FOREGROUND_SERVICE_STOP'
                               when events.type=23 THEN 'ACTIVITY_STOPPED'
                               when events.type=26 THEN 'DEVICE_SHUTDOWN'
                               when events.type=27 THEN 'DEVICE_STARTUP'
                               else events.type
                           END as eventtype
                    FROM events
                    INNER JOIN packages ON events.package_id=packages._id
                    ORDER by timestamps
                """
                queryforgalaxy = """
                    SELECT usageEvents.eventId,
                           datetime(usageEvents.timeStamp/1000, 'UNIXEPOCH') as timestamp,
                           foundPackages.name, usageEvents.eventType,
                           CASE
                               when usageEvents.eventType=1 THEN 'ACTIVITY_RESUMED'
                               when usageEvents.eventType=2 THEN 'ACTIVITY_PAUSED'
                               when usageEvents.eventType=5 THEN 'CONFIGURATION_CHANGE'
                               when usageEvents.eventType=7 THEN 'USER_INTERACTION'
                               when usageEvents.eventType=10 THEN 'NOTIFICATION PANEL'
                               when usageEvents.eventType=11 THEN 'STANDBY_BUCKET_CHANGED'
                               when usageEvents.eventType=12 THEN 'NOTIFICATION'
                               when usageEvents.eventType=15 THEN 'SCREEN_INTERACTIVE (Screen on for full user interaction)'
                               when usageEvents.eventType=16 THEN 'SCREEN_NON_INTERACTIVE (Screen on in Non-interactive state or completely turned off)'
                               when usageEvents.eventType=17 THEN 'KEYGUARD_SHOWN || POSSIBLE DEVICE LOCK'
                               when usageEvents.eventType=18 THEN 'KEYGUARD_HIDDEN || DEVICE UNLOCK'
                               when usageEvents.eventType=19 THEN 'FOREGROUND_SERVICE START'
                               when usageEvents.eventType=20 THEN 'FOREGROUND_SERVICE_STOP'
                               when usageEvents.eventType=23 THEN 'ACTIVITY_STOPPED'
                               when usageEvents.eventType=26 THEN 'DEVICE_SHUTDOWN'
                               when usageEvents.eventType=27 THEN 'DEVICE_STARTUP'
                               else usageEvents.eventType
                           END as eventTypeDescription
                    FROM usageEvents
                    INNER JOIN foundPackages ON usageEvents.pkgId=foundPackages.pkgId
                    ORDER BY timestamp
                """
                wellbing_success = False
                for target_file in ["/data/data/com.google.android.apps.wellbeing/databases/app_usage",
                            "/data/data/com.samsung.android.forest/databases/dwbCommon.db"]:
                    if self.adb_file_exists(target_file):
                        local_temp = "temp_db.db"
                        if self.adb_pull_file(target_file, local_temp):
                            df = self.execute_wellbing_query_local(
                                local_temp,
                                queryforpixel if "wellbeing" in target_file else queryforgalaxy
                            )
                            self.log("******************************************")
                            self.log(f"[6] [PATH : {target_file}]")
                            self.log(str(df))
                            self.log("******************************************\n")
                            wellbing_success = True
                            if self.gui_instance and (df is None or str(df).strip() == "" or str(df).strip() == "None"):
                                self.gui_instance.add_artifact_data("6", "wellbing", target_file, None, "시간 정보가 없습니다.")
                            break
                if not wellbing_success:
                    self.log("There is no wellbing file in device.")
                    # ????????????? ???
                    if self.gui_instance:
                        self.gui_instance.add_artifact_data("6", "wellbing", "", None, "파일이 존재하지 않습니다.")

    def process_internal_zip(self, user_id):
                internal_success = False
                targets = [
            "Dump/data/data/com.android.providers.media/databases/internal.db",
            f"Dump/data/user/{user_id}/com.google.android.providers.media.module/database/internal.db",
                    "Dump/data/data/com.android.providers.media.module/databases/internal.db",
            "Dump/data/data/com.google.android.providers.media.module/databases/internal.db",
                    f"Dump/data/user/{user_id}/com.android.providers.media.module/databases/internal.db"
                ]
                self.log("[경로 후보] internal.db ZIP 검색 경로:")
                for t in targets:
                    self.log(f"  - {t}")
                for target_file in targets:
                    if self.search_zip(target_file):
                        dbresult = self.execute_wellbing_query(target_file, None)
                        self.log("******************************************")
                        self.log(f"[7] [PATH : {target_file}]")
                        if dbresult:
                            self.timestamp_process(dbresult, artifact_id="7", path=target_file, name="internal.db")
                            self.log("******************************************\n")
                            internal_success = True
                            break
                if not internal_success:
                    self.log("Internal DB file not found in ZIP.")
                    # ????????????? ???
                    if self.gui_instance:
                        self.gui_instance.add_artifact_data("7", "internal.db", "", None, "Internal DB ???????? ????????.")

    def process_internal_folder(self, user_id):
        self.process_internal_zip(user_id)  # 동일한 로직
    
    def process_internal_adb(self, user_id):
        internal_success = False
        targets = [
            f"/data/data/com.android.providers.media/databases/internal.db",
            f"/data/user/{user_id}/com.google.android.providers.media.module/databases/internal.db",
            "/data/data/com.android.providers.media.module/databases/internal.db",
            f"/data/user/{user_id}/com.android.providers.media.module/databases/internal.db"
        ]
        self.log("[경로 후보] internal.db ADB 검색 경로:")
        for t in targets:
            self.log(f"  - {t}")
        for target_file in targets:
            if self.adb_file_exists(target_file):
                local_temp = "temp_db.db"
                if self.adb_pull_file(target_file, local_temp):
                    result = self.execute_internal_query_local(local_temp)
                    self.log("******************************************")
                    self.log(f"[7] [PATH : {target_file}]")
                    if result:
                        self.timestamp_process(result, artifact_id="7", path=target_file, name="internal.db")
                    else:
                        # No timestamp found
                        if self.gui_instance:
                            self.gui_instance.add_artifact_data("7", "internal.db", target_file, None, "No timestamp found.")
                    self.log("******************************************\n")
                    internal_success = True
                    break
        if not internal_success:
            self.log("Internal DB file not found on device.")
            # Internal DB not found
            if self.gui_instance:
                self.gui_instance.add_artifact_data("7", "internal.db", "", None, "Internal DB file not found.")

    def _parse_err_content(self, content, file_path):
        """eRR.p 내용 파싱 (공통 로직)"""
        parsed = self.parse_err_rst_stat(content)
        if parsed and self.gui_instance:
            for dt_str, dt_obj in parsed:
                self.gui_instance.add_artifact_data(
                    "8",
                    "eRR.p (RST_STAT)",
                    file_path,
                    dt_obj,
                    None,
                    is_kst=True,
                    original_time=dt_str
                )
        return parsed
    
    def process_err(self):
        """eRR.p 처리 (모든 모드 공통)"""
        if self.choice == "2":  # ADB
            target_file = '/data/system/users/service/data/eRR.p'
        else:  # ZIP or Folder
                target_file = 'Dump/data/system/users/service/data/eRR.p'
        
        if self._file_exists_by_mode(target_file):
            result = self._read_file_by_mode(target_file)
            parsed = self._parse_err_content(result, target_file)
            if not parsed and self.gui_instance:
                self.gui_instance.add_artifact_data("8", "eRR.p", target_file, None, str(result) if result else "파일 내용 없음")
        else:
            result = "eRR.p 파일이 존재하지 않습니다."
            if self.gui_instance:
                self.gui_instance.add_artifact_data("8", "eRR.p", target_file, None, "파일이 존재하지 않습니다.")
        
        self.log("******************************************")
        self.log(f"[8] [PATH : {target_file}]")
        self.log(str(result))
        self.log("******************************************\n")
    
    def process_err_zip(self):
        """ZIP 모드용 (하위 호환성)"""
        self.process_err()
    
    def process_err_folder(self):
        """Folder 모드용 (하위 호환성)"""
        self.process_err()
    
    def process_err_adb(self):
        """ADB 모드용 (하위 호환성)"""
        self.process_err()
    
    def _parse_ulr_content(self, content, file_path):
        """ULR_PERSISTENT_PREFS.xml 내용 파싱 (공통 로직)"""
        if not content:
            return False
        
        pattern = r'<long name="reportingAutoenableManagerInitTimeMillisKey"\s+value="(\d+)"'
        matches = re.findall(pattern, content)
        if matches:
            self.log("******************************************")
            self.log(f"[9] [PATH : {file_path}]")
            # millisecond를 second로 변환
            timestamp_ms = int(matches[0])
            timestamp_s = timestamp_ms / 1000.0
            self.timestamp_process(timestamp_s, artifact_id="9", path=file_path, name="ULR_PERSISTENT_PREFS.xml")
            self.log("******************************************\n")
            return True
        else:
            self.log_parse_failure(file_path, "ULR_PERSISTENT_PREFS.xml 값 없음", content)
        return False
    
    def process_ulr(self, user_id):
        """ULR_PERSISTENT_PREFS.xml 처리 (모든 모드 공통)"""
        ulr_success = False
        found_path = None
        pattern = r'<long name="reportingAutoenableManagerInitTimeMillisKey"\s+value="(\d+)"'
        
        # 모드에 따라 경로 설정
        if self.choice == "2":  # ADB
            targets = [
                f"/data/data/com.google.android.gms/shared_prefs/ULR_PERSISTENT_PREFS.xml",
                f"/data/user/{user_id}/com.google.android.gms/shared_prefs/ULR_PERSISTENT_PREFS.xml"
            ]
        else:  # ZIP or Folder
            targets = [
                "Dump/data/data/com.google.android.gms/shared_prefs/ULR_PERSISTENT_PREFS.xml",
                f"Dump/data/user/{user_id}/com.google.android.gms/shared_prefs/ULR_PERSISTENT_PREFS.xml"
            ]
        
        for target_file in targets:
            if self._file_exists_by_mode(target_file):
                found_path = target_file
                try:
                    if self.choice in ["1", "3"]:  # ZIP or Folder
                        extracted, matches = self.search_timestamp_in_property(target_file, pattern)
                        if extracted is not None and matches:
                            self.log("******************************************")
                            self.log(f"[9] [PATH : {target_file}]")
                            # millisecond를 second로 변환
                            timestamp_ms = int(matches[0])
                            timestamp_s = timestamp_ms / 1000.0
                            self.timestamp_process(timestamp_s, artifact_id="9", path=target_file, name="ULR_PERSISTENT_PREFS.xml")
                            self.log("******************************************\n")
                            ulr_success = True
                            break
                        else:
                            content = self._read_file_by_mode(target_file)
                            self.log_parse_failure(target_file, "ULR_PERSISTENT_PREFS.xml 값 없음", content)
                    else:  # ADB
                        content = self._read_file_by_mode(target_file)
                        if self._parse_ulr_content(content, target_file):
                            ulr_success = True
                            break
                except Exception as e:
                    self.log(f"[9] ULR_PERSISTENT_PREFS.xml 처리 중 오류: {e}")
        
        if not ulr_success:
            self.log("******************************************")
            self.log("[9] [ULR_PERSISTENT_PREFS.xml 파일이 존재하지 않거나 값이 없습니다.]")
            self.log("******************************************\n")
            if self.gui_instance:
                self.gui_instance.add_artifact_data(
                    "9",
                    "ULR_PERSISTENT_PREFS.xml",
                    found_path or "",
                    None,
                    "파일이 존재하지 않거나 값이 없습니다."
                )
    
    def process_ulr_zip(self, user_id):
        """ZIP 모드용 (하위 호환성)"""
        self.process_ulr(user_id)
    
    def process_ulr_folder(self, user_id):
        """Folder 모드용 (하위 호환성)"""
        self.process_ulr(user_id)
    
    def process_ulr_adb(self, user_id):
        """ADB 모드용 (하위 호환성)"""
        self.process_ulr(user_id)

    def parse_err_rst_stat(self, content):
        """eRR.p ??RST_STAT ?????? ??? ??? (KST)"""
        if not content:
            return []
        matches = []
        pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\+?(\d{4})?.*?RST_STAT", re.IGNORECASE)
        for line in content.splitlines():
            m = pattern.search(line)
            if not m:
                continue
            dt_str = m.group(1)
            try:
                dt_obj = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                matches.append((dt_str, dt_obj))
            except Exception:
                continue
        return matches

    def search_zip(self, target_file):
        """ZIP 파일 또는 해제된 폴더에서 파일 검색"""
        try:
            if self.choice == "1":
                if target_file not in self.file_list:
                    self.log(f"[경로 후보] ZIP에 없음: {target_file}")
                    return None
                else:
                    return target_file
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file)
                if actual_path and os.path.exists(actual_path):
                    return actual_path
                else:
                    # 경로 후보 로깅
                    candidates = [os.path.join(self.base_path, target_file)]
                    if isinstance(target_file, str) and target_file.startswith("Dump/"):
                        candidates.append(os.path.join(self.base_path, target_file[len("Dump/"):]))
                    self.log(f"[경로 후보] 파일 없음: {target_file}")
                    for cand in candidates:
                        self.log(f"  - {cand}")
                    return None
            else:
                return None
        except Exception as e:
            self.log(f"파일 검색 중 오류({e})")
            return None
    
    def get_actual_path(self, logical_path):
        """logical 경로를 실제 파일 시스템 경로로 변환"""
        if not self.base_path:
            return None
        actual_path = os.path.join(self.base_path, logical_path)
        if os.path.exists(actual_path):
            return actual_path
        # Dump/ 접두어가 없는 폴더 구조 대응
        if isinstance(logical_path, str) and logical_path.startswith("Dump/"):
            alt_path = os.path.join(self.base_path, logical_path[len("Dump/"):])
            if os.path.exists(alt_path):
                return alt_path
        return actual_path

    def log_parse_failure(self, file_path, reason, content=None):
        """파싱 실패 원인 상세 로그"""
        self.log(f"[파싱 실패] {file_path} - {reason}")
        if content:
            snippet = content[:300].replace("\n", "\\n")
            self.log(f"  내용 미리보기: {snippet}...")

    def read_file(self, target_file):
        """ZIP 파일 또는 해제된 폴더에서 파일 읽기"""
        try:
            if self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    if target_file not in zip_ref.namelist():
                        return None
                    with zip_ref.open(target_file) as file:
                        raw = file.read()
                        for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                            try:
                                return raw.decode(enc)
                            except Exception:
                                continue
                        return raw.decode("utf-8", errors="ignore")
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file) if isinstance(target_file, str) and not os.path.isabs(target_file) else target_file
                if not actual_path or not os.path.exists(actual_path):
                    return None
                with open(actual_path, 'rb') as file:
                    raw = file.read()
                for enc in ("utf-8", "utf-8-sig", "cp949", "utf-16le", "utf-16be"):
                    try:
                        return raw.decode(enc)
                    except Exception:
                        continue
                return raw.decode("utf-8", errors="ignore")
            else:
                return None
        except Exception as e:
            self.log(f"파일 {target_file}을(를) 읽을 수 없습니다. {e}")
            return None

    def read_file_bytes(self, target_file):
        """ZIP 파일 또는 해제된 폴더에서 파일을 bytes로 읽기"""
        try:
            if self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    if target_file not in zip_ref.namelist():
                        return None
                    with zip_ref.open(target_file) as file:
                        return file.read()
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file) if isinstance(target_file, str) and not os.path.isabs(target_file) else target_file
                if not actual_path or not os.path.exists(actual_path):
                    return None
                with open(actual_path, "rb") as f:
                    return f.read()
            else:
                return None
        except Exception as e:
            self.log(f"파일 {target_file} bytes 읽기 실패: {e}")
            return None

    def parse_xiaomi_last_log_timeline(self, content_text):
        """Xiaomi(MIUI) last_log에서 타임라인 파싱"""
        if not content_text:
            return None

        base_dt = None
        base_rel = None
        for line in content_text.splitlines():
            if "get_system_time=" not in line:
                continue
            m = re.search(r'^\[\s*(\d+\.\d+)\]\s+.*get_system_time=(\d{4}-\d{2}-\d{2})-(\d{2}:\d{2}:\d{2})', line)
            if m:
                base_rel = float(m.group(1))
                base_dt = datetime.strptime(f"{m.group(2)} {m.group(3)}", "%Y-%m-%d %H:%M:%S")
                break

        if base_dt is None or base_rel is None:
            return None

        keywords = [
            "get_system_time=",
            "-- Wiping data",
            "Formatting /data",
            "Info: format successful",
            "Data wipe complete",
            "Saving new_status",
            "enter finish_recovery",
        ]

        timeline = []
        for line in content_text.splitlines():
            m = re.match(r'^\[\s*(\d+\.\d+)\]\s+(.*)$', line)
            if not m:
                continue
            rel = float(m.group(1))
            msg = m.group(2)
            if any(k in msg for k in keywords):
                abs_dt = base_dt + timedelta(seconds=(rel - base_rel))
                abs_str = abs_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " KST"
                timeline.append((abs_str, rel, msg))

        return {
            "base_dt": base_dt,
            "base_rel": base_rel,
            "timeline": timeline,
        }

    def get_mod_time_from_zip(self, target_file):
        """ZIP 파일 또는 해제된 폴더에서 파일 수정 시간 가져오기"""
        try:
            if self.choice == "1":
                if target_file not in self.file_list:
                    self.log(f"{target_file}이 없습니다")
                    return None
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    info = zip_ref.getinfo(target_file)
                mod_time = datetime(*info.date_time)
                return mod_time
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file) if isinstance(target_file, str) and not os.path.isabs(target_file) else target_file
                if not actual_path or not os.path.exists(actual_path):
                    self.log(f"{target_file}이 없습니다")
                    return None
                mod_time = datetime.fromtimestamp(os.path.getmtime(actual_path))
                return mod_time
            else:
                return None
        except Exception as e:
            self.log(f"파일 수정 시간 가져오기 중 오류: {e}")
            return None

    def search_timestamp_in_property(self, target_file, pattern):
        """ZIP 파일 또는 해제된 폴더에서 타임스탬프 검색"""
        try:
            content = None
            if self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    if target_file not in zip_ref.namelist():
                        return None, None
                    with zip_ref.open(target_file) as file:
                        raw_bytes = file.read()
                        # 여러 인코딩 시도
                        for enc in ['utf-8-sig', 'utf-8', 'cp949', 'latin-1']:
                            try:
                                content = raw_bytes.decode(enc)
                                break
                            except UnicodeDecodeError:
                                continue
                        if content is None:
                            # 모든 인코딩 실패 시 errors='ignore'로 시도
                            content = raw_bytes.decode('utf-8', errors='ignore')
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file) if isinstance(target_file, str) and not os.path.isabs(target_file) else target_file
                if not actual_path or not os.path.exists(actual_path):
                    return None, None
                # 여러 인코딩 시도
                for enc in ['utf-8-sig', 'utf-8', 'cp949', 'latin-1']:
                    try:
                        with open(actual_path, 'r', encoding=enc) as file:
                            content = file.read()
                        break
                    except (UnicodeDecodeError, FileNotFoundError):
                        continue
                if content is None:
                    # 모든 인코딩 실패 시 errors='ignore'로 시도
                    try:
                        with open(actual_path, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                    except Exception:
                        return None, None
            else:
                return None, None
            
            if content is None:
                return None, None
            
            extracted_values = {}
            matches = re.findall(pattern, content)
            if matches:
                extracted_values[target_file] = matches
            else:
                self.log("no matches in property\n")
            return extracted_values, matches
        except Exception as e:
            self.log(f"파일 {target_file}을(를) 찾을 수 없습니다. {e}")
            return None, None

    def extract_from_binary_xml(self, target_file, adb_mode=False):
        pattern_pixel = r'<pkg[^>]*n="com\.google\.android\.(?:pixel\.)?setupwizard"[^>]*>.*?<st[^>]*\br="(\d+)"'
        pattern_galaxy = r'<pkg[^>]*n="com\.sec\.android\.app\.?SecSetupWizard"[^>]*>.*?<st[^>]*\br="(\d+)"'
        script_name = 'ccl_abx.py'
        try:
            if adb_mode:
                binary_content = self.adb_read_binary_file(target_file)
            elif self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    if target_file not in zip_ref.namelist():
                        self.log(f"파일 {target_file}이(가) ZIP 파일에 존재하지 않습니다.")
                        return None
                    with zip_ref.open(target_file) as file:
                        binary_content = file.read()
            elif self.choice == "3":
                actual_path = self.get_actual_path(target_file) if isinstance(target_file, str) and not os.path.isabs(target_file) else target_file
                if not actual_path or not os.path.exists(actual_path):
                    self.log(f"파일 {target_file}이(가) 폴더에 존재하지 않습니다.")
                    return None
                with open(actual_path, "rb") as file:
                    binary_content = file.read()
            else:
                return None
            
            if not os.path.exists(script_name):
                self.log(f"경고: {script_name} 파일을 찾을 수 없습니다. appops.xml 처리를 건너뜁니다.")
                return None
            
            with open("temp_binary_file", "wb") as temp_file:
                temp_file.write(binary_content)
            
            python_cmd = "python"
            try:
                subprocess.run([python_cmd, "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                python_cmd = "python3"
                try:
                    subprocess.run([python_cmd, "--version"], capture_output=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.log(f"경고: Python을 찾을 수 없습니다. appops.xml 처리를 건너뜁니다.")
                    return None
            
            command = [python_cmd, script_name, "temp_binary_file"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                self.log(f"ccl_abx.py 실행 실패 (exit code: {result.returncode})")
                if result.stderr:
                    self.log(f"오류 메시지: {result.stderr}")
                if result.stdout:
                    self.log(f"출력: {result.stdout}")
                self.last_abx_output = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
                return None
            
            results = result.stdout.strip()
            if not results:
                self.log("ccl_abx.py가 출력을 생성하지 않았습니다.")
                self.last_abx_output = "ccl_abx.py 출력 없음"
                return None
            self.last_abx_output = results
                
            matches = re.findall(pattern_pixel, results, re.DOTALL | re.IGNORECASE)
            if not matches:
                matches = re.findall(pattern_galaxy, results, re.DOTALL | re.IGNORECASE)
            if not matches:
                # fallback: 모든 r="숫자" 패턴
                matches = re.findall(r'\br="(\d+)"', results)
            timestamps = []
            for match in matches:
                if isinstance(match, tuple):
                    timestamps.append(match[0])
                else:
                    timestamps.append(match)
            if timestamps:
                self.log("추출된 값: " + str(matches))
            else:
                preview = results[:500].replace("\n", "\\n")
                self.log(f"ccl_abx.py 출력에 매칭 없음. 미리보기: {preview}...")
            return timestamps
        except zipfile.BadZipFile as e:
            self.log(f"Invalid ZIP file: {e}")
            return None
        except Exception as e:
            self.log(f"오류 발생: {e}")
            return None

    def timestamp_process(self, value, artifact_id=None, path=None, name=None, original_time=None, is_kst=None):
        """타임스탬프 처리 및 GUI에 데이터 추가"""
        result_time = None
        if original_time is None:
            original_time = value  # 원본 시간이 지정되지 않으면 value 사용
        if isinstance(value, datetime):
            # 이미 datetime인 경우
            # bootstat는 이미 KST이므로 is_kst=True로 표시
            is_kst = (artifact_id == "1")
            if is_kst:
                result_time = value  # KST로 간주
                self.log(f"Datetime (KST): {value}")
            else:
                result_time = value  # UTC로 간주
                self.log(f"Datetime (UTC): {value}")
        else:
            try:
                epoch_value = int(value)
                if epoch_value > 253402300799:
                    epoch_value /= 1000
                result_time = datetime.utcfromtimestamp(epoch_value)
                self.log(f"Epoch value: {value} -> UTC: {result_time}")
            except (ValueError, OverflowError) as e:
                self.log(f"Invalid or out-of-range epoch value: {value}. Error: {e}")

            # Epoch 파싱이 실패했을 때만 ISO 형식 시도
            if result_time is None and isinstance(value, str):
                iso_candidate = value.strip()
                if iso_candidate.endswith("Z"):
                    iso_candidate = iso_candidate.replace("Z", "+00:00")
                # 날짜/시간 형식 가능성이 있는 문자열만 시도
                if any(ch in iso_candidate for ch in ("-", "T", ":", "+")):
                    try:
                        result_time = datetime.fromisoformat(iso_candidate)
                        self.log(f"UTC timestamp: {iso_candidate} -> UTC: {result_time}")
                    except ValueError as e2:
                        self.log(f"Invalid UTC timestamp: {iso_candidate}. Error: {e2}")

        # GUI에 데이터 추가
        if result_time and artifact_id and self.gui_instance:
            display_name = name if name else "알 수 없음"
            display_path = path if path else ""
            # is_kst가 명시적으로 지정되지 않으면 기본 규칙 적용
            if is_kst is None:
                # bootstat는 KST, recovery.log와 last_log는 UTC 0
                is_kst = (artifact_id == "1")
                if artifact_id in ["21", "22"]:  # recovery.log와 last_log는 UTC 0
                    is_kst = False
            self.gui_instance.add_artifact_data(
                artifact_id,
                display_name,
                display_path,
                result_time,
                None,
                is_kst=is_kst,
                original_time=original_time
            )

        return result_time
    
    def collect_folder_files(self, folder_path):
        """폴더 내 모든 파일의 logical 경로 수집"""
        file_list = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                logical_path = os.path.relpath(full_path, folder_path)
                logical_path = logical_path.replace('\\', '/')
                file_list.append(logical_path)
        return file_list

    def get_user_path(self):
        if self.choice == "1":
            user_ids = set()
            for file in self.file_list:
                if file.startswith("Dump/data/user/"):
                    parts = file.split('/')
                    if len(parts) > 3:
                        user_ids.add(parts[3])
            if user_ids:
                self.log(f"추출된 USER 값: {user_ids}")
                return list(user_ids)[-1]
            else:
                self.log("ZIP 파일에서 사용자 정보를 찾을 수 없습니다.")
                return None
        elif self.choice == "3":
            user_ids = set()
            for file in self.file_list:
                if file.startswith("Dump/data/user/") or file.startswith("data/user/"):
                    parts = file.split('/')
                    if "user" in parts:
                        user_idx = parts.index("user")
                        if user_idx + 1 < len(parts):
                            user_ids.add(parts[user_idx + 1])
            if user_ids:
                self.log(f"추출된 USER 값: {user_ids}")
                return list(user_ids)[-1]
            else:
                self.log("폴더에서 사용자 정보를 찾을 수 없습니다.")
                return None
        elif self.choice == "2":
            try:
                result = subprocess.check_output(self.get_adb_args('shell', 'ls', '/data/user/'), text=True)
                user_ids = result.strip().split()
                user_id = user_ids[0] if user_ids else None
                if not user_id:
                    raise ValueError("사용자 ID를 확인할 수 없습니다.")
                return user_id
            except subprocess.CalledProcessError as e:
                self.log(f"ADB 명령 실행 실패: {e}")
                return None

    # ----------------- ADB 전용 헬퍼 함수 -----------------
    def find_adb_path(self):
        """ADB 실행 파일 경로 찾기"""
        # 먼저 PATH에서 adb 찾기 시도
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(["where", "adb"], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True, 
                                      timeout=3)
            else:  # Linux/Mac
                result = subprocess.run(["which", "adb"], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True, 
                                      timeout=3)
            
            if result.returncode == 0 and result.stdout.strip():
                adb_path = result.stdout.strip().split('\n')[0]
                if os.path.exists(adb_path):
                    return adb_path
        except Exception:
            pass
        
        # 일반적인 Android SDK 경로 확인 (Windows)
        if os.name == 'nt':
            common_paths = [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Android', 'Sdk', 'platform-tools', 'adb.exe'),
                os.path.join(os.environ.get('ProgramFiles', ''), 'Android', 'android-sdk', 'platform-tools', 'adb.exe'),
                os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Android', 'android-sdk', 'platform-tools', 'adb.exe'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Android', 'Sdk', 'platform-tools', 'adb.exe'),
            ]
            for path in common_paths:
                if path and os.path.exists(path):
                    return path
        
        # 일반적인 경로 확인 (Linux/Mac)
        else:
            common_paths = [
                os.path.expanduser('~/Android/Sdk/platform-tools/adb'),
                os.path.expanduser('~/Library/Android/sdk/platform-tools/adb'),
                '/usr/local/bin/adb',
                '/usr/bin/adb',
            ]
            for path in common_paths:
                if os.path.exists(path):
                    return path
        
        return None
    
    def get_adb_command(self):
        """ADB 명령어 반환 (경로 포함)"""
        adb_path = self.find_adb_path()
        if adb_path:
            return adb_path
        # 경로를 찾지 못하면 'adb'만 반환 (PATH에 있을 수 있음)
        return "adb"
    
    def get_adb_args(self, *args):
        """ADB 명령 인자 생성 (여러 디바이스가 있을 때 -s 옵션 추가)"""
        adb_cmd = self.get_adb_command()
        cmd_list = [adb_cmd]
        # 여러 디바이스가 있을 때 디바이스 ID 지정
        if self.adb_device_id:
            cmd_list.extend(["-s", self.adb_device_id])
        cmd_list.extend(args)
        return cmd_list
    
    def check_adb_connection(self):
        """ADB 연결 상태 확인"""
        adb_cmd = self.get_adb_command()
        
        # ADB 실행 파일이 존재하는지 확인
        if adb_cmd != "adb" and not os.path.exists(adb_cmd):
            self.log("=" * 60)
            self.log("오류: ADB를 찾을 수 없습니다.")
            self.log("=" * 60)
            self.log("ADB를 설치하거나 PATH에 추가해주세요.")
            self.log("")
            self.log("Windows에서 ADB 설치 방법:")
            self.log("1. Android SDK Platform-Tools 다운로드:")
            self.log("   https://developer.android.com/studio/releases/platform-tools")
            self.log("2. 다운로드한 platform-tools 폴더의 adb.exe 경로를 PATH에 추가")
            self.log("3. 또는 adb.exe가 있는 폴더 경로를 환경 변수에 추가")
            self.log("")
            self.log("일반적인 ADB 경로:")
            self.log("- %LOCALAPPDATA%\\Android\\Sdk\\platform-tools\\adb.exe")
            self.log("- %USERPROFILE%\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe")
            self.log("=" * 60)
            return False
        
        try:
            result = subprocess.run([adb_cmd, "devices"], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True, 
                                  timeout=5)
            if result.returncode != 0:
                self.log(f"ADB 명령 실행 실패: {result.stderr}")
                return False
            
            # devices 명령 출력에서 실제 연결된 디바이스 확인
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                self.log("연결된 디바이스가 없습니다.")
                self.log("USB 디버깅이 활성화되어 있고 디바이스가 연결되어 있는지 확인하세요.")
                return False
            
            # "device" 또는 "unauthorized" 상태 확인
            devices_found = False
            device_list = []
            for line in lines[1:]:
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        device_id = parts[0]
                        status = parts[1]
                        if status == 'device':
                            devices_found = True
                            device_list.append(device_id)
                            self.log(f"디바이스 발견: {device_id} ({status})")
                        elif 'unauthorized' in status:
                            self.log(f"디바이스 인증 필요: {device_id} ({status})")
                            self.log("디바이스에서 USB 디버깅 권한을 허용해주세요.")
            
            # 여러 디바이스가 있을 때 첫 번째 디바이스 선택
            if len(device_list) > 1:
                self.adb_device_id = device_list[0]
                self.log(f"여러 디바이스가 연결되어 있습니다. 첫 번째 디바이스 사용: {self.adb_device_id}")
            elif len(device_list) == 1:
                self.adb_device_id = device_list[0]
            
            return devices_found
        except subprocess.TimeoutExpired:
            self.log("ADB 연결 확인 시간 초과")
            return False
        except FileNotFoundError:
            self.log("=" * 60)
            self.log("오류: ADB를 찾을 수 없습니다.")
            self.log("=" * 60)
            self.log("ADB가 설치되어 있고 PATH에 추가되어 있는지 확인하세요.")
            return False
        except Exception as e:
            self.log(f"ADB 연결 확인 중 오류: {e}")
            return False
    
    def check_root_access(self):
        """루트 권한 확인"""
        adb_cmd = self.get_adb_command()
        try:
            # su 명령으로 id 확인 (루트면 uid=0)
            result = subprocess.run([adb_cmd, "shell", "su", "-c", "id"],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  text=True,
                                  timeout=5)
            
            if result.returncode == 0:
                # uid=0이면 루트 권한
                if "uid=0" in result.stdout:
                    self.log("루트 권한 확인됨.")
                    return True
                else:
                    self.log(f"루트 권한 없음. 현재 사용자: {result.stdout.strip()}")
                    return False
            else:
                # su 명령 실패 (루트 권한 없음 또는 su가 거부됨)
                error_msg = result.stderr.strip() if result.stderr else "알 수 없는 오류"
                if "not found" in error_msg.lower() or "permission denied" in error_msg.lower():
                    self.log("루트 권한 없음: su 명령을 실행할 수 없습니다.")
                else:
                    self.log(f"루트 권한 확인 실패: {error_msg}")
                return False
        except (subprocess.TimeoutExpired, Exception) as e:
            self.log(f"루트 권한 확인 중 오류: {e}")
            return False
    
    def adb_file_exists(self, file_path):
        """ADB를 통해 파일 존재 여부 확인 (루트 권한 필요)"""
        adb_cmd = self.get_adb_command()
        try:
            result = subprocess.run([adb_cmd, "shell", "su", "-c", f"test -f {file_path} && echo 'exists'"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if result.returncode == 0 and "exists" in result.stdout:
                return True
            # 대체 방법: ls 명령 사용
            result = subprocess.run([adb_cmd, "shell", "su", "-c", f"ls {file_path}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if result.returncode == 0 and "No such file" not in result.stderr:
                return True
            return False
        except subprocess.TimeoutExpired:
            self.log(f"파일 존재 확인 시간 초과: {file_path}")
            return False
        except Exception as e:
            self.log(f"파일 존재 확인 중 오류 ({file_path}): {e}")
            return False

    def adb_read_file(self, file_path, decode='utf-8'):
        """ADB를 통해 파일 읽기 (루트 권한 필요)"""
        adb_cmd = self.get_adb_command()
        try:
            result = subprocess.run([adb_cmd, "shell", "su", "-c", f"cat {file_path}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            if result.stderr and result.stderr.strip():
                # stderr에 실제 오류가 있는 경우만 로그
                if "Permission denied" in result.stderr or "No such file" not in result.stderr:
                    self.log(f"파일 읽기 경고 ({file_path}): {result.stderr.strip()}")
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log(f"파일 읽기 시간 초과: {file_path}")
            return ""
        except Exception as e:
            self.log(f"파일 읽기 오류 ({file_path}): {e}")
            return ""
    
    def adb_read_file_bytes(self, file_path):
        """ADB를 통해 파일을 바이트로 읽기 (루트 권한 필요)"""
        adb_cmd = self.get_adb_command()
        try:
            result = subprocess.run([adb_cmd, "shell", "su", "-c", f"cat {file_path}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if result.stderr and result.stderr.strip():
                # stderr에 실제 오류가 있는 경우만 로그
                if "Permission denied" in result.stderr or "No such file" not in result.stderr:
                    self.log(f"파일 읽기 경고 ({file_path}): {result.stderr.strip()}")
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log(f"파일 읽기 시간 초과: {file_path}")
            return b""
        except Exception as e:
            self.log(f"파일 읽기 오류 ({file_path}): {e}")
            return b""

    def adb_read_binary_file(self, file_path):
        """ADB를 통해 바이너리 파일 읽기 (루트 권한 필요)"""
        adb_cmd = self.get_adb_command()
        try:
            result = subprocess.run([adb_cmd, "shell", "su", "-c", f"cat {file_path}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if result.stderr:
                error_msg = result.stderr.decode('utf-8', errors='ignore')
                if "Permission denied" in error_msg or ("No such file" not in error_msg and error_msg.strip()):
                    self.log(f"바이너리 파일 읽기 경고 ({file_path}): {error_msg.strip()}")
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log(f"바이너리 파일 읽기 시간 초과: {file_path}")
            return None
        except Exception as e:
            self.log(f"바이너리 파일 읽기 중 오류 ({file_path}): {e}")
            return None

    def adb_get_mod_time(self, file_path):
        adb_cmd = self.get_adb_command()
        result = subprocess.run([adb_cmd, "shell", "su", "-c", f"stat {file_path}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            self.log(f"Error stat-ing {file_path}: {result.stderr}")
            return None
        for line in result.stdout.splitlines():
            if "Modify:" in line:
                match = re.search(r"Modify:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                if match:
                    date_str = match.group(1)
                    dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    return dt
        return None

    def adb_pull_file(self, remote_path, local_path):
        """ADB를 통해 파일 pull (루트 권한이 필요한 파일의 경우 임시로 복사 후 pull)"""
        adb_cmd = self.get_adb_command()
        temp_path = "/data/local/tmp/temp_file"
        try:
            # root 권한으로 임시 파일 생성
            copy_result = subprocess.run([adb_cmd, "shell", "su", "-c", f"cp {remote_path} {temp_path}"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)

            if copy_result.returncode == 0:
                # 임시 파일 pull
                pull_result = subprocess.run([adb_cmd, "pull", temp_path, local_path],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                # 임시 파일 삭제
                subprocess.run([adb_cmd, "shell", "su", "-c", f"rm {temp_path}"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

                if pull_result.returncode == 0:
                    return True
                else:
                    self.log(f"파일 pull 실패 ({remote_path}): {pull_result.stderr}")
                    return False
            else:
                # 복사 실패 시 직접 pull 시도
                pull_result = subprocess.run([adb_cmd, "pull", remote_path, local_path],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                if pull_result.returncode == 0:
                    return True
                else:
                    self.log(f"파일 pull 실패 ({remote_path}): {pull_result.stderr}")
                    return False
        except subprocess.TimeoutExpired:
            self.log(f"파일 pull 시간 초과: {remote_path}")
            return False
        except Exception as e:
            self.log(f"파일 pull 중 오류 ({remote_path}): {e}")
            return False

    def execute_wellbing_query_local(self, db_path, query):
        try:
            import sqlite3
        except ImportError as e:
            error_msg = str(e)
            if "DLL" in error_msg or "_sqlite3" in error_msg:
                self.log("******************************************")
                self.log("[오류] SQLite 모듈을 불러올 수 없습니다.")
                self.log("Python 환경의 SQLite DLL이 손상되었거나 누락되었습니다.")
                self.log("해결 방법:")
                self.log("1. Python 환경을 재설정하거나")
                self.log("2. 다른 Python 환경을 사용하거나")
                self.log("3. wellbing/internal 기능을 사용하지 않도록 선택하세요.")
                self.log("******************************************")
            else:
                self.log(f"SQLite 모듈을 불러올 수 없습니다: {e}")
            return None
        except Exception as e:
            self.log(f"SQLite 모듈 로드 중 예상치 못한 오류: {e}")
            return None
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            columns = [description[0] for description in cursor.description]
            results = cursor.fetchall()
            df = pd.DataFrame(results, columns=columns)
            conn.close()
            return df
        except Exception as e:
            self.log(f"Error in execute_wellbing_query_local: {e}")
            return None

    def execute_internal_query_local(self, db_path):
        try:
            import sqlite3
        except ImportError as e:
            error_msg = str(e)
            if "DLL" in error_msg or "_sqlite3" in error_msg:
                self.log("******************************************")
                self.log("[오류] SQLite 모듈을 불러올 수 없습니다.")
                self.log("Python 환경의 SQLite DLL이 손상되었거나 누락되었습니다.")
                self.log("해결 방법:")
                self.log("1. Python 환경을 재설정하거나")
                self.log("2. 다른 Python 환경을 사용하거나")
                self.log("3. wellbing/internal 기능을 사용하지 않도록 선택하세요.")
                self.log("******************************************")
            else:
                self.log(f"SQLite 모듈을 불러올 수 없습니다: {e}")
            return None
        except Exception as e:
            self.log(f"SQLite 모듈 로드 중 예상치 못한 오류: {e}")
            return None
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT MIN(date_added) AS earliest_date FROM files;")
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except Exception as e:
            self.log(f"Error in execute_internal_query_local: {e}")
            return None

    # ----------------- 기존 execute_wellbing_query (ZIP/폴더 모드) -----------------
    def execute_wellbing_query(self, db_file, query):
        try:
            import sqlite3
        except ImportError as e:
            error_msg = str(e)
            if "DLL" in error_msg or "_sqlite3" in error_msg:
                self.log("******************************************")
                self.log("[오류] SQLite 모듈을 불러올 수 없습니다.")
                self.log("Python 환경의 SQLite DLL이 손상되었거나 누락되었습니다.")
                self.log("해결 방법:")
                self.log("1. Python 환경을 재설정하거나")
                self.log("2. 다른 Python 환경을 사용하거나")
                self.log("3. wellbing/internal 기능을 사용하지 않도록 선택하세요.")
                self.log("******************************************")
                return "SQLite 모듈을 사용할 수 없습니다."
            else:
                self.log(f"SQLite 모듈을 불러올 수 없습니다: {e}")
                return "SQLite 모듈을 사용할 수 없습니다."
        except Exception as e:
            self.log(f"SQLite 모듈 로드 중 예상치 못한 오류: {e}")
            return "SQLite 모듈을 사용할 수 없습니다."
        
        try:
            if self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    with zip_ref.open(db_file) as file:
                        db_content = file.read()
            elif self.choice == "3":
                actual_path = self.get_actual_path(db_file) if isinstance(db_file, str) and not os.path.isabs(db_file) else db_file
                if not actual_path or not os.path.exists(actual_path):
                    raise FileNotFoundError(f"데이터베이스 파일을 찾을 수 없습니다: {db_file}")
                with open(actual_path, "rb") as file:
                    db_content = file.read()
            else:
                return None
            
            with open("temp_db.db", "wb") as temp_file:
                temp_file.write(db_content)
            mem_db = sqlite3.connect(":memory:")
            disk_db = sqlite3.connect("temp_db.db")
            with disk_db:
                disk_db.backup(mem_db)
            cursor = mem_db.cursor()
            if query is None:
                cursor.execute("SELECT MIN(date_added) AS earliest_date FROM files;")
                result = cursor.fetchone()
                mem_db.close()
                disk_db.close()
                return result[0] if result else None
            if "6" in self.artifact_choices or "0" in self.artifact_choices:
                cursor.execute(query)
                columns = [description[0] for description in cursor.description]
                results = cursor.fetchall()
                df = pd.DataFrame(results, columns=columns)
                try:
                    filtered_df = df[df["package_name"].isin(["com.google.android.setupwizard", "android"])]
                except Exception as e:
                    filtered_df = df[df["name"].isin(["setupwizard", "android"])]
                mem_db.close()
                disk_db.close()
                return filtered_df
            else:
                cursor.execute("SELECT MIN(date_added) AS earliest_date FROM files;")
                result = cursor.fetchone()
                mem_db.close()
                disk_db.close()
                return result[0]
        except sqlite3.Error as e:
            self.log(f"SQLite 오류 발생: {e}")
            return "wellbeing 데이터가 기록되지 않았습니다."
        except Exception as e:
            self.log(f"오류 발생: {e}")
            return None
    
    def deep_search(self, search_times, result_callback, progress_callback=None, time_tolerance_seconds=300):
        """Deep search - search files using extracted times
        
        Args:
            search_times: 검색할 시간 정보 리스트
            result_callback: 결과를 전달할 콜백 함수
            progress_callback: 진행률을 전달할 콜백 함수
            time_tolerance_seconds: 시간 매칭 오차 허용 범위 (초, 기본값: 300초 = 5분)
        """
        self.log("=" * 60)
        self.log("Deep Search started")
        self.log(f"시간 매칭 오차 허용 범위: ±{time_tolerance_seconds}초 (±{time_tolerance_seconds/60:.1f}분)")
        self.log("=" * 60)
        
        # 검색할 시간 형식 생성
        search_patterns = []
        for time_info in search_times:
            time_dt = time_info['time']
            original_time = time_info.get('original_time')
            
            # 여러 형식으로 변환
            patterns = {}
            
            # 1. Epoch (초)
            epoch_sec = int(time_dt.timestamp())
            patterns['epoch_sec'] = str(epoch_sec)
            
            # 2. Epoch (밀리초)
            epoch_ms = int(time_dt.timestamp() * 1000)
            patterns['epoch_ms'] = str(epoch_ms)
            
            # 3. 날짜 형식들
            patterns['date_iso'] = time_dt.strftime('%Y-%m-%d %H:%M:%S')
            patterns['date_slash'] = time_dt.strftime('%Y/%m/%d %H:%M:%S')
            patterns['date_dot'] = time_dt.strftime('%Y.%m.%d %H:%M:%S')
            patterns['date_only'] = time_dt.strftime('%Y-%m-%d')
            
            # 4. 원본 시간 형식
            if original_time:
                if isinstance(original_time, datetime):
                    patterns['original_datetime'] = original_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    patterns['original_value'] = str(original_time)
            
            search_patterns.append({
                'time_str': time_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'patterns': patterns,
                'time_info': time_info
            })
        
        # 파일 목록 가져오기
        if self.choice == "1":
            files_to_search = self.file_list
        elif self.choice == "3":
            files_to_search = self.file_list
        elif self.choice == "2":
            # ADB 모드에서는 주요 경로의 파일들 검색
            files_to_search = self.get_adb_file_list()
        else:
            files_to_search = []
        
        # 바이너리 파일 필터링
        text_files = []
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.apk', '.so', '.dex', '.bin', '.dat', '.zip', '.rar']
        for file_path in files_to_search:
            if not any(file_path.lower().endswith(ext) for ext in skip_extensions):
                text_files.append(file_path)
        
        total_files = len(text_files)
        self.log(f"검색할 파일 수: {total_files}")
        self.log(f"검색할 시간 패턴 수: {len(search_patterns)}")
        
        match_count = 0
        processed_count = 0
        
        # 각 파일에서 검색
        for idx, file_path in enumerate(text_files):
            try:
                # 파일 읽기
                if self.choice == "1":
                    content = self.read_file_for_search(file_path)
                    raw_bytes = self.read_file_bytes(file_path)
                elif self.choice == "3":
                    content = self.read_file_for_search(file_path)
                    raw_bytes = self.read_file_bytes(file_path)
                elif self.choice == "2":
                    content = self.adb_read_file_for_search(file_path)
                    raw_bytes = self.adb_read_file_bytes(file_path)
                else:
                    content = None
                    raw_bytes = b""
                
                processed_count += 1
                
                # 진행률 업데이트 (10개마다 또는 마지막 파일)
                if progress_callback and (processed_count % 10 == 0 or processed_count == total_files):
                    progress_callback.emit(processed_count, total_files)
                
                if not content:
                    continue
                content_lower = content.lower()

                # 파일 수정 시간 기반 매칭
                file_mtime = self.get_file_mod_time_for_search(file_path)
                if file_mtime:
                    for search_info in search_patterns:
                        time_dt = search_info['time_info']['time']
                        diff_sec = abs((file_mtime - time_dt).total_seconds())
                        if diff_sec <= time_tolerance_seconds:
                            match_count += 1
                            diff_min = diff_sec / 60
                            if diff_sec < 60:
                                display_value = f"{file_mtime.strftime('%Y-%m-%d %H:%M:%S')} (차이: {diff_sec:.0f}초)"
                            else:
                                display_value = f"{file_mtime.strftime('%Y-%m-%d %H:%M:%S')} (차이: {diff_min:.1f}분)"
                            result_callback.emit(
                                search_info['time_str'],
                                file_path,
                                "file_mtime",
                                display_value
                            )
                
                # 각 시간 패턴으로 검색
                for search_info in search_patterns:
                    for pattern_name, pattern_value in search_info['patterns'].items():
                        if not pattern_value:
                            continue
                        pattern_value_str = str(pattern_value)
                        pattern_value_lower = pattern_value_str.lower()
                        if pattern_value_lower in content_lower:
                            # 날짜만 매칭인데 실제로 시간 정보가 붙어 있는 경우는 날짜-only 결과를 건너뜀
                            if pattern_name == 'date_only':
                                idx = content_lower.find(pattern_value_lower)
                                if idx != -1:
                                    context = content_lower[max(0, idx - 3):idx + 20]
                                    if re.search(r"\d{2}:\d{2}:\d{2}", context):
                                        continue
                            match_count += 1
                            
                            # 매칭된 형식에 따라 시간 정보 유무 표시
                            display_value = pattern_value_str
                            if pattern_name == 'date_only':
                                display_value = f"{pattern_value_str} (시간 없음)"
                            elif 'datetime' in pattern_name or 'iso' in pattern_name or 'slash' in pattern_name or 'dot' in pattern_name:
                                # 시간 정보가 포함된 형식인지 확인
                                if ':' not in pattern_value_str:
                                    display_value = f"{pattern_value_str} (시간 없음)"
                            
                            result_callback.emit(
                                search_info['time_str'],
                                file_path,
                                pattern_name,
                                display_value
                            )
                            self.log(f"매칭 발견: {file_path} - {pattern_name}: {display_value}")

                    # HEX/바이너리 패턴 검색
                    if raw_bytes:
                        bin_patterns = self.build_binary_patterns(search_info['time_info']['time'])
                        for bin_name, bin_value in bin_patterns.items():
                            offset = raw_bytes.find(bin_value)
                            if offset != -1:
                                match_count += 1
                                hex_str = " ".join(f"{b:02X}" for b in bin_value)
                                display_value = f"{bin_name} @0x{offset:X}: {hex_str}"
                                result_callback.emit(
                                    search_info['time_str'],
                                    file_path,
                                    f"hex_{bin_name}",
                                    display_value
                                )
                                self.log(f"매칭 발견(HEX): {file_path} - {bin_name} @0x{offset:X}")
            
            except Exception as e:
                # 파일 읽기 실패는 무시하고 계속
                processed_count += 1
                if progress_callback and (processed_count % 10 == 0 or processed_count == total_files):
                    progress_callback.emit(processed_count, total_files)
                continue
        
        # 최종 진행률 업데이트
        if progress_callback:
            progress_callback.emit(total_files, total_files)
        
        self.log(f"Deep Search completed. Total {match_count} matches found")
        self.log("=" * 60)
    
    def read_file_for_search(self, file_path):
        """검색용 파일 읽기 (텍스트 파일만)"""
        try:
            if self.choice == "1":
                with zipfile.ZipFile(self.zipfile, 'r') as zip_ref:
                    if file_path not in zip_ref.namelist():
                        return None
                    with zip_ref.open(file_path) as file:
                        try:
                            content = file.read().decode('utf-8', errors='ignore')
                            return content
                        except:
                            try:
                                content = file.read().decode('cp949', errors='ignore')
                                return content
                            except:
                                return None
            elif self.choice == "3":
                actual_path = self.get_actual_path(file_path) if isinstance(file_path, str) and not os.path.isabs(file_path) else file_path
                if not actual_path or not os.path.exists(actual_path):
                    return None
                try:
                    with open(actual_path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
                except:
                    try:
                        with open(actual_path, 'r', encoding='cp949', errors='ignore') as f:
                            return f.read()
                    except:
                        return None
            return None
        except:
            return None
    
    def adb_read_file_for_search(self, file_path):
        """ADB 모드에서 검색용 파일 읽기"""
        try:
            content = self.adb_read_file(file_path)
            return content if content else None
        except:
            return None
    
    def get_adb_file_list(self):
        """ADB 모드에서 검색할 파일 목록 가져오기"""
        file_list = []
        search_paths = [
            "/data/data",
            "/data/system",
            "/data/misc",
            "/data/property",
            "/cache",
        ]
        
        for base_path in search_paths:
            try:
                result = subprocess.run(self.get_adb_args('shell', 'su', '-c', f'find {base_path} -type f 2>/dev/null | head -1000'),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    file_list.extend([f for f in files if f.strip()])
            except:
                continue
        
        return file_list[:5000]  # 최대 5000개 파일로 제한


class SavedResultsExplorer(QDialog):
    """파일 탐색기 스타일의 저장된 결과 뷰어"""
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("저장된 분석 결과")
        self.setMinimumSize(1200, 800)
        self.results_dir = os.path.join(os.path.dirname(__file__), "saved_results")
        self.current_data = None
        self.current_filepath = None  # 현재 선택된 파일 경로
        self.init_ui()
        self.load_results()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # 상단 툴바
        toolbar = QHBoxLayout()
        btn_refresh = QPushButton("새로고침")
        btn_refresh.clicked.connect(self.load_results)
        btn_delete = QPushButton("삭제")
        btn_delete.clicked.connect(self.delete_selected)
        toolbar.addWidget(btn_refresh)
        toolbar.addWidget(btn_delete)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # 분할 뷰 (왼쪽: 목록, 오른쪽: 상세)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # 왼쪽: 결과 목록 (트리 뷰)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["결과 목록"])
        self.tree.setRootIsDecorated(True)
        self.tree.itemSelectionChanged.connect(self.on_selection_changed)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        splitter.addWidget(self.tree)
        
        # 오른쪽: 상세 정보
        detail_widget = QWidget()
        detail_layout = QVBoxLayout()
        detail_widget.setLayout(detail_layout)
        
        # 편집 가능한 필드들
        edit_group = QGroupBox("상세 정보 편집")
        edit_layout = QVBoxLayout()
        edit_group.setLayout(edit_layout)
        
        # 차수
        order_layout = QHBoxLayout()
        order_layout.addWidget(QLabel("차수:"))
        self.order_edit = QLineEdit()
        self.order_edit.setPlaceholderText("예: 1차 또는 Ex1")
        order_layout.addWidget(self.order_edit)
        edit_layout.addLayout(order_layout)
        
        # 제조사
        manufacturer_layout = QHBoxLayout()
        manufacturer_layout.addWidget(QLabel("제조사:"))
        self.manufacturer_edit = QLineEdit()
        self.manufacturer_edit.setPlaceholderText("예: 삼성")
        manufacturer_layout.addWidget(self.manufacturer_edit)
        edit_layout.addLayout(manufacturer_layout)
        
        # 모델명
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("모델명:"))
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("예: SM-S921N")
        model_layout.addWidget(self.model_edit)
        edit_layout.addLayout(model_layout)
        
        # 시나리오명
        scenario_layout = QHBoxLayout()
        scenario_layout.addWidget(QLabel("시나리오명:"))
        self.scenario_edit = QLineEdit()
        self.scenario_edit.setPlaceholderText("예: 공장초기화")
        scenario_layout.addWidget(self.scenario_edit)
        edit_layout.addLayout(scenario_layout)
        
        # 확정된 초기화 시간
        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel("확정된 초기화 시간:"))
        self.confirmed_time_edit = QLineEdit()
        self.confirmed_time_edit.setPlaceholderText("초기화 시간을 입력하세요")
        time_layout.addWidget(self.confirmed_time_edit)
        edit_layout.addLayout(time_layout)
        
        # 메모
        memo_layout = QVBoxLayout()
        memo_layout.addWidget(QLabel("메모:"))
        self.memo_edit = QTextEdit()
        self.memo_edit.setPlaceholderText("메모를 입력하세요...")
        self.memo_edit.setMaximumHeight(100)
        memo_layout.addWidget(self.memo_edit)
        edit_layout.addLayout(memo_layout)
        
        # 저장 버튼
        btn_save = QPushButton("저장")
        btn_save.clicked.connect(self.save_edited_info)
        btn_save.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 5px; }")
        edit_layout.addWidget(btn_save)
        
        detail_layout.addWidget(edit_group)
        
        # 읽기 전용 정보 (저장 시간, 원본 파일 등)
        info_group = QGroupBox("기본 정보 (읽기 전용)")
        info_layout = QVBoxLayout()
        info_group.setLayout(info_layout)
        
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(150)
        info_layout.addWidget(self.info_text)
        
        detail_layout.addWidget(info_group)
        
        # 상세 정보 탭
        self.detail_tabs = QTabWidget()
        detail_layout.addWidget(self.detail_tabs)
        
        # 아티팩트 결과 탭
        self.artifact_tabs = QTabWidget()
        self.detail_tabs.addTab(self.artifact_tabs, "아티팩트 결과")
        
        # Summary results tab
        self.summary_table = QTableWidget()
        self.summary_table.setColumnCount(4)
        self.summary_table.setHorizontalHeaderLabels(["Artifact", "Path", "Time", "Original Time"])
        self.summary_table.horizontalHeader().setStretchLastSection(True)
        self.summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.summary_table.setSortingEnabled(True)
        self.detail_tabs.addTab(self.summary_table, "Summary Results")
        
        # Deep search results tab
        self.deep_search_table = QTableWidget()
        self.deep_search_table.setColumnCount(4)
        self.deep_search_table.setHorizontalHeaderLabels(["Search Time", "File Path", "Match Format", "Match Value"])
        self.deep_search_table.horizontalHeader().setStretchLastSection(True)
        self.deep_search_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.detail_tabs.addTab(self.deep_search_table, "Deep Search Results")
        
        splitter.addWidget(detail_widget)
        splitter.setSizes([300, 900])
        
        # 닫기 버튼
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
    
    def load_results(self):
        """저장된 결과 목록 로드"""
        self.tree.clear()
        
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir, exist_ok=True)
            return
        
        # 파일명 기반으로 그룹화 (차수/모델명 추출)
        file_list = []
        for filename in os.listdir(self.results_dir):
            if not filename.endswith('.json'):
                continue
            
            filepath = os.path.join(self.results_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 사용자가 지정한 파일명 사용 (없으면 실제 파일명 사용)
                saved_filename = data.get('saved_filename', filename)
                display_name = saved_filename.replace('.json', '')
                
                # 파일명 파싱
                parts = display_name.split()
                order = '기타'
                manufacturer = ''
                model = ''
                scenario = ''
                
                if len(parts) >= 1:
                    # Check for order pattern: "N차" or "ExN" format
                    if '차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit()):
                        order = parts[0]
                        remaining = parts[1:] if len(parts) > 1 else []
                    else:
                        remaining = parts
                    
                    if len(remaining) >= 3:
                        manufacturer = remaining[0]
                        model = remaining[1]
                        scenario = ' '.join(remaining[2:])
                    elif len(remaining) == 2:
                        manufacturer = remaining[0]
                        model = remaining[1]
                    elif len(remaining) == 1:
                        model = remaining[0]
                
                file_list.append({
                    'filename': filename,
                    'filepath': filepath,
                    'data': data,
                    'display_name': display_name,
                    'order': order,
                    'manufacturer': manufacturer,
                    'model': model,
                    'scenario': scenario
                })
            except Exception as e:
                continue
        
        # 파일명에서 차수, 제조사, 모델명 추출하여 그룹화
        groups = {}
        for file_info in file_list:
            order = file_info.get('order', '기타')
            manufacturer = file_info.get('manufacturer', '')
            model = file_info.get('model', '')
            
            # 그룹화 키 생성 (차수 + 제조사 + 모델명, 시나리오명은 제외)
            if manufacturer:
                group_key = f"{order} {manufacturer} {model}".strip()
            else:
                group_key = f"{order} {model}".strip()
            
            if order not in groups:
                groups[order] = {}
            if group_key not in groups[order]:
                groups[order][group_key] = []
            
            groups[order][group_key].append(file_info)
        
        # 트리 구성
        for order in sorted(groups.keys()):
            order_item = QTreeWidgetItem(self.tree)
            order_item.setText(0, order)
            order_item.setExpanded(True)
            
            for group_key in sorted(groups[order].keys()):
                model_item = QTreeWidgetItem(order_item)
                model_item.setText(0, group_key)
                model_item.setExpanded(True)
                
                # 해당 그룹의 파일들
                for file_info in groups[order][group_key]:
                    result_item = QTreeWidgetItem(model_item)
                    result_item.setText(0, file_info['display_name'])
                    result_item.setData(0, Qt.UserRole, file_info['filepath'])
                    result_item.setData(0, Qt.UserRole + 1, file_info['data'])
    
    def on_selection_changed(self):
        """선택 변경 시 상세 정보 표시"""
        selected = self.tree.selectedItems()
        if not selected:
            return
        
        item = selected[0]
        filepath = item.data(0, Qt.UserRole)
        data = item.data(0, Qt.UserRole + 1)
        
        if not filepath or not data:
            return
        
        self.current_data = data
        self.current_filepath = filepath  # 파일 경로 저장 (저장 시 필요)
        self.display_result(data)
    
    def on_double_click(self, item, column):
        """더블 클릭 시 상세 정보 표시"""
        self.on_selection_changed()
    
    def display_result(self, data):
        """결과 상세 정보 표시"""
        # 기본 정보 (모델명, 초기화 시간, 메모 포함)
        timestamp = data.get('timestamp', 'N/A')
        try:
            if timestamp != 'N/A':
                dt = datetime.fromisoformat(timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        confirmed_time = data.get('confirmed_time', 'N/A')
        model_name = data.get('model_name', 'N/A')
        memo = data.get('memo', '')
        
        # 파일명에서 파싱된 정보 가져오기 (없으면 파일명에서 파싱)
        saved_filename = data.get('saved_filename', '')
        order = data.get('order', '')
        manufacturer = data.get('manufacturer', '')
        scenario = data.get('scenario', '')
        
        # 파일명에서 파싱 (저장된 값이 없으면)
        if not order or not manufacturer or not scenario:
            if saved_filename:
                parts = saved_filename.replace('.json', '').split()
                # Check for order pattern: "N차" or "ExN" format
                if len(parts) >= 1 and ('차' in parts[0] or (parts[0].startswith('Ex') and len(parts[0]) > 2 and parts[0][2:].isdigit())):
                    if not order:
                        order = parts[0]
                    if len(parts) >= 2 and not manufacturer:
                        manufacturer = parts[1]
                    if len(parts) >= 3 and (not model_name or model_name == 'N/A'):
                        model_name = parts[2]
                    if len(parts) >= 4 and not scenario:
                        scenario = ' '.join(parts[3:])
        
        # 편집 가능한 필드에 값 설정
        self.order_edit.setText(order if order else '')
        self.manufacturer_edit.setText(manufacturer if manufacturer else '')
        self.model_edit.setText(model_name if model_name != 'N/A' else '')
        self.scenario_edit.setText(scenario if scenario else '')
        self.confirmed_time_edit.setText(confirmed_time if confirmed_time != 'N/A' else '')
        self.memo_edit.setPlainText(memo)
        
        # 읽기 전용 정보 표시
        info_text = f"""저장 시간: {timestamp}
원본 파일: {data.get('file_path', 'N/A')}
소스: {data.get('source', 'N/A')}
"""
        self.info_text.setPlainText(info_text)
        
        # 아티팩트 결과
        self.artifact_tabs.clear()
        artifact_names = {
            "1": "bootstat",
            "2-1": "recovery.log",
            "2-2": "last_log",
            "3": "suggestions.xml",
            "4": "persistent_properties",
            "5": "appops",
            "6": "wellbing",
            "7": "internal",
            "8": "eRR.p",
            "9": "ULR_PERSISTENT_PREFS.xml"
        }
        
        for artifact_id, artifact_data_list in data.get('artifact_data', {}).items():
            if not artifact_data_list:
                continue
            
            table = QTableWidget()
            table.setColumnCount(5)
            table.setHorizontalHeaderLabels(["아티팩트", "경로", "시간", "원본 시간", "메시지"])
            table.horizontalHeader().setStretchLastSection(True)
            table.setEditTriggers(QTableWidget.NoEditTriggers)
            table.setAlternatingRowColors(True)
            
            for data_item in artifact_data_list:
                row = table.rowCount()
                table.insertRow(row)
                
                table.setItem(row, 0, QTableWidgetItem(data_item.get('name', '')))
                table.setItem(row, 1, QTableWidgetItem(data_item.get('path', '')))
                
                # 시간 표시
                if data_item.get('time'):
                    try:
                        dt = datetime.fromisoformat(data_item['time'])
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                        if data_item.get('is_kst'):
                            time_str += " KST"
                        else:
                            time_str += " UTC"
                    except:
                        time_str = str(data_item.get('time', ''))
                else:
                    time_str = ""
                
                table.setItem(row, 2, QTableWidgetItem(time_str))
                table.setItem(row, 3, QTableWidgetItem(data_item.get('original_time', '')))
                table.setItem(row, 4, QTableWidgetItem(data_item.get('message', '')))
            
            table.resizeColumnsToContents()
            artifact_name = artifact_names.get(artifact_id, f"아티팩트 {artifact_id}")
            self.artifact_tabs.addTab(table, artifact_name)
        
        # Summary results
        self.summary_table.setRowCount(0)
        all_times = []
        for artifact_id, artifact_data_list in data.get('artifact_data', {}).items():
            for data_item in artifact_data_list:
                if data_item.get('time'):
                    try:
                        dt = datetime.fromisoformat(data_item['time'])
                        all_times.append({
                            'time': dt,
                            'artifact_id': artifact_id,
                            'data': data_item
                        })
                    except:
                        pass
        
        all_times.sort(key=lambda x: x['time'])
        
        for item in all_times:
            row = self.summary_table.rowCount()
            self.summary_table.insertRow(row)
            
            artifact_name = artifact_names.get(item['artifact_id'], f"Artifact {item['artifact_id']}")
            data_item = item['data']
            
            self.summary_table.setItem(row, 0, QTableWidgetItem(artifact_name))
            self.summary_table.setItem(row, 1, QTableWidgetItem(data_item.get('path', '')))
            
            time_str = item['time'].strftime("%Y-%m-%d %H:%M:%S")
            if data_item.get('is_kst'):
                time_str += " KST"
            else:
                time_str += " UTC"
            
            self.summary_table.setItem(row, 2, QTableWidgetItem(time_str))
            self.summary_table.setItem(row, 3, QTableWidgetItem(data_item.get('original_time', '')))
        
        self.summary_table.resizeColumnsToContents()
        
        # Deep search results
        self.deep_search_table.setRowCount(0)
        for result in data.get('deep_search_results', []):
            row = self.deep_search_table.rowCount()
            self.deep_search_table.insertRow(row)
            self.deep_search_table.setItem(row, 0, QTableWidgetItem(result.get('search_time', '')))
            self.deep_search_table.setItem(row, 1, QTableWidgetItem(result.get('file_path', '')))
            self.deep_search_table.setItem(row, 2, QTableWidgetItem(result.get('match_format', '')))
            self.deep_search_table.setItem(row, 3, QTableWidgetItem(result.get('match_value', '')))
        
        self.deep_search_table.resizeColumnsToContents()
    
    def save_edited_info(self):
        """편집된 상세 정보 저장"""
        try:
            if not self.current_data or not self.current_filepath:
                self.show_message("오류", "저장할 데이터가 선택되지 않았습니다.")
                return
            
            # 편집된 값 가져오기
            order = self.order_edit.text().strip()
            manufacturer = self.manufacturer_edit.text().strip()
            model_name = self.model_edit.text().strip()
            scenario = self.scenario_edit.text().strip()
            confirmed_time = self.confirmed_time_edit.text().strip()
            memo = self.memo_edit.toPlainText().strip()
            
            # 데이터 업데이트
            self.current_data['order'] = order
            self.current_data['manufacturer'] = manufacturer
            self.current_data['model_name'] = model_name
            self.current_data['scenario'] = scenario
            self.current_data['confirmed_time'] = confirmed_time if confirmed_time else None
            self.current_data['memo'] = memo
            
            # 파일명도 업데이트 (차수, 제조사, 모델명, 시나리오명이 모두 있으면)
            if order and manufacturer and model_name and scenario:
                new_filename = f"{order} {manufacturer} {model_name} {scenario}.json"
                old_filename = os.path.basename(self.current_filepath)
                
                # 파일명이 변경되면 파일명도 변경
                if new_filename != old_filename:
                    new_filepath = os.path.join(self.results_dir, new_filename)
                    # 기존 파일이 있으면 덮어쓰기 확인
                    if os.path.exists(new_filepath) and new_filepath != self.current_filepath:
                        reply = QMessageBox.question(self, "파일 존재", 
                                                   f"'{new_filename}' 파일이 이미 존재합니다.\n덮어쓰시겠습니까?",
                                                   QMessageBox.Yes | QMessageBox.No)
                        if reply != QMessageBox.Yes:
                            return
                    
                    # 파일명 변경
                    try:
                        if os.path.exists(self.current_filepath):
                            os.rename(self.current_filepath, new_filepath)
                        self.current_filepath = new_filepath
                    except Exception as e:
                        self.show_message("경고", f"파일명 변경 실패: {str(e)}\n데이터는 저장되었습니다.")
                
                self.current_data['saved_filename'] = new_filename
            
            # JSON 직렬화 가능한 형태로 변환
            serializable_data = self._convert_to_json_serializable(self.current_data)
            
            # 파일 저장
            with open(self.current_filepath, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, ensure_ascii=False, indent=2)
            
            # 성공 메시지
            self.show_message("성공", "상세 정보가 저장되었습니다.")
            
            # 목록 새로고침
            self.load_results()
            
        except Exception as e:
            import traceback
            error_msg = f"저장 중 오류가 발생했습니다: {str(e)}\n{traceback.format_exc()}"
            self.show_message("오류", error_msg)
    
    def _convert_to_json_serializable(self, obj):
        """datetime 객체를 JSON 직렬화 가능한 형태로 변환"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._convert_to_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)
    
    def show_message(self, title, message):
        """메시지 표시"""
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec_()
    
    def show_question(self, title, message):
        """질문 메시지 박스 표시"""
        reply = QMessageBox.question(self, title, message, 
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        return reply
    
    def delete_selected(self):
        """선택된 결과 삭제"""
        selected = self.tree.selectedItems()
        if not selected:
            self.show_message("경고", "삭제할 결과를 선택하세요.")
            return
        
        item = selected[0]
        filepath = item.data(0, Qt.UserRole)
        
        if not filepath:
            self.show_message("경고", "유효하지 않은 선택입니다.")
            return
        
        reply = self.show_question("확인", "선택한 결과를 삭제하시겠습니까?")
        if reply == QMessageBox.Yes:
            try:
                os.remove(filepath)
                self.load_results()  # 목록 새로고침
                self.show_message("완료", "삭제되었습니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"삭제 중 오류가 발생했습니다:\n{e}")


if __name__ == "__main__":
    def qt_message_handler(mode, context, message):
        # QObject::connect 관련 경고 무시
        if "QObject::connect: Cannot queue arguments of type" in message:
            return
        if "QList<QPersistentModelIndex>" in message or "QVector<int>" in message or "QTextCursor" in message:
            return
        # 기본 동작 유지
        sys.stderr.write(message + "\n")

    qInstallMessageHandler(qt_message_handler)

    app = QApplication(sys.argv)
    window = FactoryResetGUI()
    window.show()
    sys.exit(app.exec_())
