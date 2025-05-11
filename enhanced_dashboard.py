import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
import sqlite3
from typing import Dict, Any, List, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dashboard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enhanced_dashboard")

class EnhancedDashboard:
    """
    Enhanced dashboard for phishing detection system with:
    - Detailed analysis explanations
    - Detection statistics monitoring
    - User feedback system
    - Historical trends visualization
    """
    
    def __init__(self, root):
        """Initialize the dashboard"""
        self.root = root
        self.root.title("PhishSentinel Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize database
        self.db_path = "dashboard.db"
        self._init_database()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.overview_tab = ttk.Frame(self.notebook)
        self.stats_tab = ttk.Frame(self.notebook)
        self.feedback_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.stats_tab, text="Statistics")
        self.notebook.add(self.feedback_tab, text="Feedback")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Setup tabs
        self._setup_overview_tab()
        self._setup_stats_tab()
        self._setup_feedback_tab()
        self._setup_settings_tab()
        
        # Update statistics periodically
        self._update_stats()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "ui_settings": {
                "theme": "light",
                "update_interval": 300,  # 5 minutes
                "max_history": 1000
            },
            "detection_thresholds": {
                "high_confidence": 0.8,
                "medium_confidence": 0.5,
                "low_confidence": 0.3
            }
        }
        
        try:
            if os.path.exists("phishing_detector_config.json"):
                with open("phishing_detector_config.json", 'r') as f:
                    config = json.load(f)
                logger.info("Loaded configuration from file")
                return config
            return default_config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return default_config
    
    def _init_database(self):
        """Initialize SQLite database for storing detection history and feedback"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create detections table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    email_from TEXT,
                    email_subject TEXT,
                    is_phishing BOOLEAN,
                    confidence FLOAT,
                    analysis_details TEXT
                )
            """)
            
            # Create feedback table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_correct BOOLEAN,
                    feedback_text TEXT,
                    FOREIGN KEY (detection_id) REFERENCES detections (id)
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def _setup_overview_tab(self):
        """Setup the overview tab with current status and recent detections"""
        # Create frames
        status_frame = ttk.LabelFrame(self.overview_tab, text="System Status", padding=10)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        recent_frame = ttk.LabelFrame(self.overview_tab, text="Recent Detections", padding=10)
        recent_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add status indicators
        self.status_labels = {}
        for component in ["Model", "URL Analysis", "Sender Analysis", "Image Analysis"]:
            frame = ttk.Frame(status_frame)
            frame.pack(side=tk.LEFT, padx=10)
            
            label = ttk.Label(frame, text=f"{component}:")
            label.pack(side=tk.LEFT)
            
            status = ttk.Label(frame, text="Active", foreground="green")
            status.pack(side=tk.LEFT, padx=5)
            
            self.status_labels[component] = status
        
        # Add recent detections table
        columns = ("Time", "From", "Subject", "Result", "Confidence", "Actions")
        self.recent_tree = ttk.Treeview(recent_frame, columns=columns, show="headings")
        
        # Configure columns
        for col in columns:
            self.recent_tree.heading(col, text=col)
            self.recent_tree.column(col, width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(recent_frame, orient=tk.VERTICAL, command=self.recent_tree.yview)
        self.recent_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.recent_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _setup_stats_tab(self):
        """Setup the statistics tab with graphs and metrics"""
        # Create frames
        metrics_frame = ttk.LabelFrame(self.stats_tab, text="Key Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        charts_frame = ttk.LabelFrame(self.stats_tab, text="Detection Trends", padding=10)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add metric counters
        self.metrics = {}
        for metric in ["Total Scans", "Phishing Detected", "False Positives", "Accuracy"]:
            frame = ttk.Frame(metrics_frame)
            frame.pack(side=tk.LEFT, padx=20)
            
            label = ttk.Label(frame, text=f"{metric}:")
            label.pack()
            
            value = ttk.Label(frame, text="0")
            value.pack()
            
            self.metrics[metric] = value
        
        # Create matplotlib figure for charts
        self.fig = plt.Figure(figsize=(10, 6))
        self.canvas = FigureCanvasTkAgg(self.fig, master=charts_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add subplots
        self.detection_plot = self.fig.add_subplot(121)
        self.confidence_plot = self.fig.add_subplot(122)
    
    def _setup_feedback_tab(self):
        """Setup the feedback tab for user feedback and reporting"""
        # Create frames
        report_frame = ttk.LabelFrame(self.feedback_tab, text="Report Detection Issue", padding=10)
        report_frame.pack(fill=tk.X, padx=5, pady=5)
        
        history_frame = ttk.LabelFrame(self.feedback_tab, text="Feedback History", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add reporting form
        ttk.Label(report_frame, text="Detection ID:").grid(row=0, column=0, padx=5, pady=5)
        self.detection_id_entry = ttk.Entry(report_frame)
        self.detection_id_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(report_frame, text="Issue Type:").grid(row=1, column=0, padx=5, pady=5)
        self.issue_type = ttk.Combobox(report_frame, values=["False Positive", "False Negative", "Other"])
        self.issue_type.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(report_frame, text="Description:").grid(row=2, column=0, padx=5, pady=5)
        self.feedback_text = scrolledtext.ScrolledText(report_frame, height=4)
        self.feedback_text.grid(row=2, column=1, padx=5, pady=5)
        
        submit_btn = ttk.Button(report_frame, text="Submit Feedback", command=self._submit_feedback)
        submit_btn.grid(row=3, column=1, pady=10)
        
        # Add feedback history table
        columns = ("Time", "Detection ID", "Issue Type", "Status", "Actions")
        self.feedback_tree = ttk.Treeview(history_frame, columns=columns, show="headings")
        
        # Configure columns
        for col in columns:
            self.feedback_tree.heading(col, text=col)
            self.feedback_tree.column(col, width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.feedback_tree.yview)
        self.feedback_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.feedback_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _setup_settings_tab(self):
        """Setup the settings tab for configuration"""
        # Create frames
        settings_frame = ttk.LabelFrame(self.settings_tab, text="Dashboard Settings", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        thresholds_frame = ttk.LabelFrame(self.settings_tab, text="Detection Thresholds", padding=10)
        thresholds_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add settings
        ttk.Label(settings_frame, text="Theme:").grid(row=0, column=0, padx=5, pady=5)
        self.theme_var = tk.StringVar(value=self.config.get("ui_settings", {}).get("theme", "light"))
        theme_combo = ttk.Combobox(settings_frame, textvariable=self.theme_var, values=["light", "dark"])
        theme_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Update Interval (seconds):").grid(row=1, column=0, padx=5, pady=5)
        self.interval_var = tk.StringVar(value=str(self.config.get("ui_settings", {}).get("update_interval", 300)))
        interval_entry = ttk.Entry(settings_frame, textvariable=self.interval_var)
        interval_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Add threshold settings
        thresholds = self.config.get("detection_thresholds", {})
        row = 0
        self.threshold_vars = {}
        
        for level in ["high_confidence", "medium_confidence", "low_confidence"]:
            ttk.Label(thresholds_frame, text=f"{level.replace('_', ' ').title()}:").grid(row=row, column=0, padx=5, pady=5)
            var = tk.StringVar(value=str(thresholds.get(level, 0.5)))
            self.threshold_vars[level] = var
            entry = ttk.Entry(thresholds_frame, textvariable=var)
            entry.grid(row=row, column=1, padx=5, pady=5)
            row += 1
        
        # Add save button
        save_btn = ttk.Button(self.settings_tab, text="Save Settings", command=self._save_settings)
        save_btn.pack(pady=20)
    
    def _submit_feedback(self):
        """Submit user feedback"""
        try:
            detection_id = self.detection_id_entry.get()
            issue_type = self.issue_type.get()
            feedback_text = self.feedback_text.get("1.0", tk.END).strip()
            
            if not all([detection_id, issue_type, feedback_text]):
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            # Save feedback to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO feedback (detection_id, is_correct, feedback_text)
                VALUES (?, ?, ?)
            """, (detection_id, issue_type == "False Negative", feedback_text))
            
            conn.commit()
            conn.close()
            
            # Clear form
            self.detection_id_entry.delete(0, tk.END)
            self.issue_type.set("")
            self.feedback_text.delete("1.0", tk.END)
            
            messagebox.showinfo("Success", "Feedback submitted successfully")
            self._update_feedback_history()
            
        except Exception as e:
            logger.error(f"Error submitting feedback: {e}")
            messagebox.showerror("Error", f"Error submitting feedback: {e}")
    
    def _save_settings(self):
        """Save dashboard settings"""
        try:
            # Update configuration
            if "ui_settings" not in self.config:
                self.config["ui_settings"] = {}
            
            self.config["ui_settings"]["theme"] = self.theme_var.get()
            self.config["ui_settings"]["update_interval"] = int(self.interval_var.get())
            
            if "detection_thresholds" not in self.config:
                self.config["detection_thresholds"] = {}
            
            for level, var in self.threshold_vars.items():
                self.config["detection_thresholds"][level] = float(var.get())
            
            # Save to file
            with open("phishing_detector_config.json", 'w') as f:
                json.dump(self.config, f, indent=4)
            
            messagebox.showinfo("Success", "Settings saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            messagebox.showerror("Error", f"Error saving settings: {e}")
    
    def _update_stats(self):
        """Update statistics and charts"""
        try:
            # Update database stats
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get metrics
            cursor.execute("SELECT COUNT(*) FROM detections")
            total_scans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM detections WHERE is_phishing = 1")
            phishing_detected = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM detections d
                JOIN feedback f ON d.id = f.detection_id
                WHERE d.is_phishing = 1 AND f.is_correct = 0
            """)
            false_positives = cursor.fetchone()[0]
            
            # Calculate accuracy
            total_feedback = cursor.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
            correct_predictions = cursor.execute("""
                SELECT COUNT(*) FROM feedback WHERE is_correct = 1
            """).fetchone()[0]
            
            accuracy = (correct_predictions / total_feedback * 100) if total_feedback > 0 else 0
            
            # Update metric labels
            self.metrics["Total Scans"].config(text=str(total_scans))
            self.metrics["Phishing Detected"].config(text=str(phishing_detected))
            self.metrics["False Positives"].config(text=str(false_positives))
            self.metrics["Accuracy"].config(text=f"{accuracy:.1f}%")
            
            # Get detection trends
            cursor.execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM detections
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
                LIMIT 7
            """)
            trend_data = cursor.fetchall()
            
            # Get confidence distribution
            cursor.execute("""
                SELECT confidence
                FROM detections
                WHERE timestamp >= DATE('now', '-7 days')
            """)
            confidences = [row[0] for row in cursor.fetchall()]
            
            conn.close()
            
            # Update charts
            self.detection_plot.clear()
            self.confidence_plot.clear()
            
            # Plot detection trend
            dates = [row[0] for row in trend_data]
            counts = [row[1] for row in trend_data]
            self.detection_plot.plot(dates, counts)
            self.detection_plot.set_title("Detection Trend (7 days)")
            self.detection_plot.tick_params(axis='x', rotation=45)
            
            # Plot confidence distribution
            if confidences:
                self.confidence_plot.hist(confidences, bins=20)
                self.confidence_plot.set_title("Confidence Distribution")
            
            self.fig.tight_layout()
            self.canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
        
        # Schedule next update
        update_interval = self.config.get("ui_settings", {}).get("update_interval", 300) * 1000  # Convert to milliseconds
        self.root.after(update_interval, self._update_stats)
    
    def _update_feedback_history(self):
        """Update feedback history table"""
        try:
            # Clear existing items
            for item in self.feedback_tree.get_children():
                self.feedback_tree.delete(item)
            
            # Get feedback history
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT f.timestamp, f.detection_id, 
                       CASE WHEN d.is_phishing = f.is_correct THEN 'False Negative' ELSE 'False Positive' END as issue_type,
                       'Submitted' as status
                FROM feedback f
                JOIN detections d ON f.detection_id = d.id
                ORDER BY f.timestamp DESC
                LIMIT 100
            """)
            
            # Add to table
            for row in cursor.fetchall():
                self.feedback_tree.insert("", tk.END, values=row)
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating feedback history: {e}")

def main():
    root = tk.Tk()
    dashboard = EnhancedDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
