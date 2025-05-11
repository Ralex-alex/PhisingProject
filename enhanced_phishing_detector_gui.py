import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font
from PIL import Image, ImageTk
import threading
import json
import os
import sys
import re
import time
from datetime import datetime
from enhanced_phishing_detector import EnhancedPhishingDetector

class EnhancedPhishingDetectorGUI:
    """
    Enhanced GUI for the phishing email detector.
    Features:
    - Email content input with sender and recipient fields
    - Detailed analysis results with component breakdown
    - Suspicious elements highlighting
    - File upload for email analysis
    - History tracking
    - Modern UI with the PhishSentinel logo
    """
    
    def __init__(self, root):
        """Initialize the GUI"""
        self.root = root
        self.root.title("PhishSentinel - Advanced Phishing Detection")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize theme
        self.current_theme = self.config.get("ui_settings", {}).get("theme", "light")
        
        # Set app icon and logo
        self.logo_path = self.config.get("ui_settings", {}).get("logo_path", "PhishSentinelLogo.png")
        self._setup_icon_and_logo()
        
        # Configure basic style
        self.style = ttk.Style()
        
        # Create the detector in a separate thread
        self.detector = None
        self.detector_ready = False
        self.loading_detector = False
        
        # Create main frame with two panels
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create menu bar
        self._setup_menu()
        
        # Create left panel (input)
        self.left_panel = ttk.Frame(self.main_frame, padding="10")
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Create right panel (results)
        self.right_panel = ttk.Frame(self.main_frame, padding="10")
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Setup UI components
        self._setup_left_panel()
        self._setup_right_panel()
        
        # Create loading indicator
        self.loading_frame = ttk.Frame(self.root)
        self.loading_label = ttk.Label(self.loading_frame, text="Analyzing...", style="Header.TLabel")
        self.loading_progress = ttk.Progressbar(self.loading_frame, mode='indeterminate')
        
        # Now that all widgets are created, setup the styles
        self._setup_styles()
        
        # Start loading the detector in a background thread
        self.load_detector_thread = threading.Thread(target=self._load_detector)
        self.load_detector_thread.daemon = True
        self.load_detector_thread.start()
        
        # Show initial status
        self.status_label.config(text="Loading phishing detection engine... Please wait.")
        
        # Check detector status periodically
        self._check_detector_status()
    
    def _load_config(self):
        """Load configuration from file"""
        default_config = {
            "ui_settings": {
                "logo_path": "PhishSentinelLogo.png",
                "theme": "light",
                "show_detailed_analysis": True
            }
        }
        
        try:
            if os.path.exists("phishing_detector_config.json"):
                with open("phishing_detector_config.json", 'r') as f:
                    return json.load(f)
            return default_config
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return default_config
    
    def _setup_icon_and_logo(self):
        """Setup application icon and logo"""
        try:
            # Set app icon if available
            if os.path.exists("shield_icon.ico"):
                self.root.iconbitmap("shield_icon.ico")
            
            # Load logo
            if os.path.exists(self.logo_path):
                self.logo_image = Image.open(self.logo_path)
                # Resize logo to fit nicely
                self.logo_image = self.logo_image.resize((200, 200), Image.LANCZOS)
                self.logo_photo = ImageTk.PhotoImage(self.logo_image)
            else:
                self.logo_photo = None
        except Exception as e:
            print(f"Error loading icon or logo: {e}")
            self.logo_photo = None
    
    def _setup_styles(self):
        """Setup ttk styles for the application"""
        # Configure the theme
        self.style.configure(".", font=("Arial", 11))
        
        if self.current_theme == "dark":
            # Dark theme colors
            bg_color = "#2E2E2E"
            fg_color = "#FFFFFF"
            input_bg = "#3E3E3E"
            button_bg = "#4A4A4A"
            
            # Configure dark theme styles
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("TLabel", background=bg_color, foreground=fg_color)
            self.style.configure("TButton", background=button_bg, foreground=fg_color)
            self.style.configure("TEntry", fieldbackground=input_bg, foreground=fg_color)
            self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
            self.style.configure("TNotebook", background=bg_color, foreground=fg_color)
            self.style.configure("TNotebook.Tab", background=button_bg, foreground=fg_color)
            
            # Configure special labels
            self.style.configure("Header.TLabel", font=("Arial", 16, "bold"), background=bg_color, foreground=fg_color)
            self.style.configure("Result.TLabel", font=("Arial", 14), background=bg_color, foreground=fg_color)
            self.style.configure("Safe.TLabel", foreground="#4CAF50", font=("Arial", 16, "bold"), background=bg_color)
            self.style.configure("Danger.TLabel", foreground="#F44336", font=("Arial", 16, "bold"), background=bg_color)
            self.style.configure("Warning.TLabel", foreground="#FFC107", font=("Arial", 16, "bold"), background=bg_color)
            
            # Configure root window
            self.root.configure(background=bg_color)
            
            # Configure text widgets
            text_config = {
                "background": input_bg,
                "foreground": fg_color,
                "insertbackground": fg_color,
                "selectbackground": "#666666",
                "selectforeground": fg_color
            }
            
            # Apply text widget configuration
            for widget_name in ["body_text", "summary_text", "suspicious_text", 
                              "recommendations_text", "details_text"]:
                if hasattr(self, widget_name):
                    widget = getattr(self, widget_name)
                    if widget is not None:
                        widget.configure(**text_config)
        else:
            # Light theme colors
            bg_color = "#FFFFFF"
            fg_color = "#000000"
            input_bg = "#FFFFFF"
            button_bg = "#F0F0F0"
            
            # Configure light theme styles
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("TLabel", background=bg_color, foreground=fg_color)
            self.style.configure("TButton", background=button_bg, foreground=fg_color)
            self.style.configure("TEntry", fieldbackground=input_bg, foreground=fg_color)
            self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
            self.style.configure("TNotebook", background=bg_color, foreground=fg_color)
            self.style.configure("TNotebook.Tab", background=button_bg, foreground=fg_color)
            
            # Configure special labels
            self.style.configure("Header.TLabel", font=("Arial", 16, "bold"))
            self.style.configure("Result.TLabel", font=("Arial", 14))
            self.style.configure("Safe.TLabel", foreground="#4CAF50", font=("Arial", 16, "bold"))
            self.style.configure("Danger.TLabel", foreground="#F44336", font=("Arial", 16, "bold"))
            self.style.configure("Warning.TLabel", foreground="#FFC107", font=("Arial", 16, "bold"))
            
            # Configure root window
            self.root.configure(background=bg_color)
            
            # Configure text widgets
            text_config = {
                "background": input_bg,
                "foreground": fg_color,
                "insertbackground": fg_color,
                "selectbackground": "#0078D7",
                "selectforeground": "#FFFFFF"
            }
            
            # Apply text widget configuration
            for widget_name in ["body_text", "summary_text", "suspicious_text", 
                              "recommendations_text", "details_text"]:
                if hasattr(self, widget_name):
                    widget = getattr(self, widget_name)
                    if widget is not None:
                        widget.configure(**text_config)
    
    def _setup_left_panel(self):
        """Setup the left panel with input fields"""
        # Add logo at the top
        if self.logo_photo:
            logo_label = ttk.Label(self.left_panel, image=self.logo_photo)
            logo_label.pack(pady=(0, 10))
        
        # Add title
        title_label = ttk.Label(self.left_panel, text="PhishSentinel", style="Header.TLabel")
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(self.left_panel, text="Advanced Phishing Detection")
        subtitle_label.pack(pady=(0, 20))
        
        # Create input frame
        input_frame = ttk.LabelFrame(self.left_panel, text="Email Details", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Add sender field with tooltip
        sender_frame = ttk.Frame(input_frame)
        sender_frame.pack(fill=tk.X, pady=(0, 5))
        
        sender_label = ttk.Label(sender_frame, text="Sender:")
        sender_label.pack(side=tk.LEFT, padx=(0, 5))
        self._create_tooltip(sender_label, "Email address of the sender")
        
        self.sender_entry = ttk.Entry(sender_frame, width=40)
        self.sender_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add recipient field with tooltip
        recipient_frame = ttk.Frame(input_frame)
        recipient_frame.pack(fill=tk.X, pady=(0, 5))
        
        recipient_label = ttk.Label(recipient_frame, text="Recipient:")
        recipient_label.pack(side=tk.LEFT, padx=(0, 5))
        self._create_tooltip(recipient_label, "Email address of the recipient")
        
        self.recipient_entry = ttk.Entry(recipient_frame, width=40)
        self.recipient_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add subject field with tooltip
        subject_frame = ttk.Frame(input_frame)
        subject_frame.pack(fill=tk.X, pady=(0, 5))
        
        subject_label = ttk.Label(subject_frame, text="Subject:")
        subject_label.pack(side=tk.LEFT, padx=(0, 5))
        self._create_tooltip(subject_label, "Subject line of the email")
        
        self.subject_entry = ttk.Entry(subject_frame, width=40)
        self.subject_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add body field with tooltip
        body_label = ttk.Label(input_frame, text="Email Body:")
        body_label.pack(anchor=tk.W, pady=(5, 5))
        self._create_tooltip(body_label, "Main content of the email")
        
        self.body_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=15)
        self.body_text.pack(fill=tk.BOTH, expand=True)
        
        # Create buttons frame
        buttons_frame = ttk.Frame(self.left_panel)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Add analyze button with tooltip
        self.analyze_button = ttk.Button(buttons_frame, text="Analyze Email (F5)", command=self._analyze_email)
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 5))
        self._create_tooltip(self.analyze_button, "Analyze the email for phishing indicators")
        
        # Add load from file button with tooltip
        self.load_button = ttk.Button(buttons_frame, text="Load from File (Ctrl+O)", command=self._load_from_file)
        self.load_button.pack(side=tk.LEFT, padx=(0, 5))
        self._create_tooltip(self.load_button, "Load email content from a file")
        
        # Add clear button with tooltip
        clear_button = ttk.Button(buttons_frame, text="Clear (Ctrl+N)", command=self._clear_fields)
        clear_button.pack(side=tk.LEFT)
        self._create_tooltip(clear_button, "Clear all input fields")
        
        # Add status label
        self.status_label = ttk.Label(self.left_panel, text="")
        self.status_label.pack(pady=5, anchor=tk.W)
        
        # Disable buttons until detector is ready
        self.analyze_button.config(state=tk.DISABLED)
        self.load_button.config(state=tk.DISABLED)
    
    def _setup_right_panel(self):
        """Setup the right panel with results display"""
        # Create result frame
        self.result_frame = ttk.LabelFrame(self.right_panel, text="Analysis Result", padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add verdict label
        self.verdict_frame = ttk.Frame(self.result_frame)
        self.verdict_frame.pack(fill=tk.X, pady=10)
        
        self.verdict_label = ttk.Label(self.verdict_frame, text="", style="Result.TLabel")
        self.verdict_label.pack(side=tk.LEFT)
        
        # Add confidence label
        self.confidence_frame = ttk.Frame(self.result_frame)
        self.confidence_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.confidence_label = ttk.Label(self.confidence_frame, text="")
        self.confidence_label.pack(side=tk.LEFT)
        
        # Add risk level progress bar
        risk_frame = ttk.Frame(self.result_frame)
        risk_frame.pack(fill=tk.X, pady=(0, 10))
        
        risk_label = ttk.Label(risk_frame, text="Risk Level:")
        risk_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.risk_progress = ttk.Progressbar(risk_frame, length=200, mode='determinate')
        self.risk_progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.risk_text = ttk.Label(risk_frame, text="")
        self.risk_text.pack(side=tk.LEFT, padx=(5, 0))
        
        # Create notebook for detailed results
        self.result_notebook = ttk.Notebook(self.result_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.result_notebook, padding=10)
        self.result_notebook.add(self.summary_frame, text="Summary")
        
        # Suspicious elements tab
        self.suspicious_frame = ttk.Frame(self.result_notebook, padding=10)
        self.result_notebook.add(self.suspicious_frame, text="Suspicious Elements")
        
        # Recommendations tab
        self.recommendations_frame = ttk.Frame(self.result_notebook, padding=10)
        self.result_notebook.add(self.recommendations_frame, text="Recommendations")
        
        # Detailed analysis tab
        self.details_frame = ttk.Frame(self.result_notebook, padding=10)
        self.result_notebook.add(self.details_frame, text="Detailed Analysis")
        
        # Setup summary tab
        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, wrap=tk.WORD, height=10)
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        self.summary_text.config(state=tk.DISABLED)
        
        # Setup suspicious elements tab
        self.suspicious_text = scrolledtext.ScrolledText(self.suspicious_frame, wrap=tk.WORD, height=10)
        self.suspicious_text.pack(fill=tk.BOTH, expand=True)
        self.suspicious_text.config(state=tk.DISABLED)
        
        # Setup recommendations tab
        self.recommendations_text = scrolledtext.ScrolledText(self.recommendations_frame, wrap=tk.WORD, height=10)
        self.recommendations_text.pack(fill=tk.BOTH, expand=True)
        self.recommendations_text.config(state=tk.DISABLED)
        
        # Setup detailed analysis tab
        self.details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
    
    def _load_detector(self):
        """Load the phishing detection engine in a background thread"""
        self.loading_detector = True
        try:
            self.detector = EnhancedPhishingDetector()
            self.detector_ready = True
        except Exception as e:
            print(f"Error loading detector: {e}")
            self.detector_ready = False
        finally:
            self.loading_detector = False
    
    def _check_detector_status(self):
        """Check if the detector has finished loading"""
        if self.loading_detector:
            # Still loading, check again later
            self.root.after(1000, self._check_detector_status)
        elif self.detector_ready:
            # Detector loaded successfully
            self.status_label.config(text="Phishing detection engine loaded successfully. Ready to analyze emails.")
            self.analyze_button.config(state=tk.NORMAL)
            self.load_button.config(state=tk.NORMAL)
        else:
            # Detector failed to load
            self.status_label.config(text="Error loading phishing detection engine. Please restart the application.")
            messagebox.showerror("Error", "Failed to initialize phishing detection engine.")
    
    def _analyze_email(self):
        """Analyze the email content for phishing indicators"""
        if not self.detector_ready:
            messagebox.showerror("Not Ready", "The phishing detection engine is not ready yet. Please wait.")
            return
        
        # Get email content
        sender = self.sender_entry.get().strip()
        recipient = self.recipient_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get("1.0", tk.END).strip()
        
        if not body:
            messagebox.showerror("Missing Content", "Please enter the email body content.")
            return
        
        # Prepare the email text (combine subject and body)
        full_text = f"Subject: {subject}\n\n{body}"
        
        # Update status
        self.status_label.config(text="Analyzing email... Please wait.")
        self.analyze_button.config(state=tk.DISABLED)
        self.load_button.config(state=tk.DISABLED)
        
        # Run analysis in a separate thread
        threading.Thread(target=self._run_analysis, args=(full_text, sender, recipient)).start()
    
    def _run_analysis(self, email_content, sender, recipient):
        """Run the analysis in a background thread"""
        try:
            # Get model prediction
            result = self.detector.analyze_email(email_content, sender, recipient)
            
            # Update UI with results
            self.root.after(0, lambda: self._display_results(result))
            
        except Exception as e:
            # Handle errors
            self.root.after(0, lambda: self._handle_analysis_error(str(e)))
    
    def _display_results(self, result):
        """Display the analysis results in the UI"""
        # Enable buttons
        self.analyze_button.config(state=tk.NORMAL)
        self.load_button.config(state=tk.NORMAL)
        
        # Update status
        self.status_label.config(text=f"Analysis completed in {result.get('analysis_time', 0):.2f} seconds")
        
        # Update verdict
        is_phishing = result.get("is_phishing", False)
        confidence = result.get("confidence", 0.0)
        risk_level = result.get("risk_level", "low")
        
        if is_phishing:
            self.verdict_label.config(
                text="⚠️ PHISHING EMAIL DETECTED ⚠️", 
                style="Danger.TLabel"
            )
        else:
            self.verdict_label.config(
                text="✓ LEGITIMATE EMAIL", 
                style="Safe.TLabel"
            )
        
        # Update confidence
        self.confidence_label.config(text=f"Confidence: {confidence:.1%}")
        
        # Update risk level
        self.risk_progress["value"] = confidence * 100
        self.risk_text.config(
            text=risk_level.upper(),
            style="Danger.TLabel" if risk_level == "high" else 
                  "Warning.TLabel" if risk_level == "medium" else 
                  "Safe.TLabel"
        )
        
        # Update summary tab
        self._update_summary_tab(result)
        
        # Update suspicious elements tab
        self._update_suspicious_tab(result)
        
        # Update recommendations tab
        self._update_recommendations_tab(result)
        
        # Update detailed analysis tab
        self._update_details_tab(result)
    
    def _update_summary_tab(self, result):
        """Update the summary tab with analysis results"""
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete("1.0", tk.END)
        
        is_phishing = result.get("is_phishing", False)
        confidence = result.get("confidence", 0.0)
        risk_level = result.get("risk_level", "low")
        
        summary = f"VERDICT: {'PHISHING' if is_phishing else 'LEGITIMATE'}\n"
        summary += f"Confidence: {confidence:.1%}\n"
        summary += f"Risk Level: {risk_level.upper()}\n\n"
        
        # Add component scores
        component_results = result.get("component_results", {})
        summary += "Component Analysis:\n"
        
        if "sender" in component_results:
            sender_score = component_results["sender"].get("risk_score", 0.0)
            summary += f"- Sender Analysis: {sender_score:.1%} risk\n"
        
        if "url" in component_results:
            url_score = component_results["url"].get("overall_risk_score", 0.0)
            summary += f"- URL Analysis: {url_score:.1%} risk\n"
        
        if "behavioral" in component_results:
            behavioral_score = component_results["behavioral"].get("risk_score", 0.0)
            summary += f"- Behavioral Analysis: {behavioral_score:.1%} risk\n"
        
        if "image" in component_results:
            image_score = component_results["image"].get("overall_risk_score", 0.0)
            summary += f"- Image Analysis: {image_score:.1%} risk\n"
        
        if "llm" in component_results:
            llm_score = component_results["llm"].get("phishing_probability", 0.0)
            summary += f"- Language Model Analysis: {llm_score:.1%} risk\n"
        
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)
    
    def _update_suspicious_tab(self, result):
        """Update the suspicious elements tab with detailed analysis"""
        self.suspicious_text.config(state=tk.NORMAL)
        self.suspicious_text.delete("1.0", tk.END)
        
        suspicious_elements = result.get("suspicious_elements", [])
        component_results = result.get("component_results", {})
        
        if not suspicious_elements and not component_results:
            self.suspicious_text.insert(tk.END, "No suspicious elements detected.")
            self.suspicious_text.config(state=tk.DISABLED)
            return
        
        # Add header
        self.suspicious_text.insert(tk.END, "SUSPICIOUS ELEMENTS ANALYSIS\n", "header")
        self.suspicious_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # Process suspicious elements
        if suspicious_elements:
            self.suspicious_text.insert(tk.END, f"Found {len(suspicious_elements)} suspicious elements:\n\n")
            
            for i, element in enumerate(suspicious_elements, 1):
                element_type = element.get("type", "unknown").upper()
                value = element.get("value", "")
                risk_score = element.get("risk_score", 0.0)
                details = element.get("details", "")
                
                # Add element header
                self.suspicious_text.insert(tk.END, f"{i}. {element_type}\n", "subheader")
                self.suspicious_text.insert(tk.END, f"   Value: {value}\n")
                self.suspicious_text.insert(tk.END, f"   Risk Score: {risk_score:.1%}\n")
                
                # Add details
                if isinstance(details, list):
                    self.suspicious_text.insert(tk.END, f"   Reasons:\n")
                    for detail in details:
                        self.suspicious_text.insert(tk.END, f"    • {detail}\n")
                else:
                    self.suspicious_text.insert(tk.END, f"   Details: {details}\n")
                
                self.suspicious_text.insert(tk.END, "\n")
        
        # Add component analysis results
        if component_results:
            self.suspicious_text.insert(tk.END, "COMPONENT ANALYSIS\n", "header")
            self.suspicious_text.insert(tk.END, "=" * 50 + "\n\n")
            
            # Sender Analysis
            if "sender" in component_results:
                sender_data = component_results["sender"]
                self.suspicious_text.insert(tk.END, "Sender Analysis:\n", "subheader")
                self._add_component_details(sender_data)
            
            # URL Analysis
            if "url" in component_results:
                url_data = component_results["url"]
                self.suspicious_text.insert(tk.END, "\nURL Analysis:\n", "subheader")
                self._add_component_details(url_data)
            
            # Behavioral Analysis
            if "behavioral" in component_results:
                behavioral_data = component_results["behavioral"]
                self.suspicious_text.insert(tk.END, "\nBehavioral Analysis:\n", "subheader")
                self._add_component_details(behavioral_data)
            
            # Language Model Analysis
            if "llm" in component_results:
                llm_data = component_results["llm"]
                self.suspicious_text.insert(tk.END, "\nLanguage Analysis:\n", "subheader")
                self._add_component_details(llm_data)
        
        # Configure text tags
        self.suspicious_text.tag_configure("header", font=("Arial", 12, "bold"))
        self.suspicious_text.tag_configure("subheader", font=("Arial", 11, "bold"))
        self.suspicious_text.tag_configure("bullet", font=("Arial", 11))
        
        self.suspicious_text.config(state=tk.DISABLED)
    
    def _add_component_details(self, component_data):
        """Helper method to add component analysis details"""
        for key, value in component_data.items():
            if key in ["risk_score", "overall_risk_score", "phishing_probability"]:
                self.suspicious_text.insert(tk.END, f"• Risk Score: {value:.1%}\n")
            elif key == "reasons" and isinstance(value, list):
                self.suspicious_text.insert(tk.END, "• Reasons:\n")
                for reason in value:
                    self.suspicious_text.insert(tk.END, f"  - {reason}\n")
            elif key == "suspicious_patterns" and isinstance(value, list):
                self.suspicious_text.insert(tk.END, "• Suspicious Patterns:\n")
                for pattern in value:
                    self.suspicious_text.insert(tk.END, f"  - {pattern}\n")
            elif key not in ["type", "value", "details"]:
                if isinstance(value, (list, dict)):
                    continue  # Skip complex nested structures
                self.suspicious_text.insert(tk.END, f"• {key.replace('_', ' ').title()}: {value}\n")
    
    def _update_recommendations_tab(self, result):
        """Update the recommendations tab"""
        self.recommendations_text.config(state=tk.NORMAL)
        self.recommendations_text.delete("1.0", tk.END)
        
        recommendations = result.get("recommendations", [])
        
        if not recommendations:
            self.recommendations_text.insert(tk.END, "No specific recommendations available.")
        else:
            self.recommendations_text.insert(tk.END, "Recommendations:\n\n")
            
            for i, recommendation in enumerate(recommendations, 1):
                self.recommendations_text.insert(tk.END, f"{i}. {recommendation}\n\n")
        
        self.recommendations_text.config(state=tk.DISABLED)
    
    def _update_details_tab(self, result):
        """Update the detailed analysis tab"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        
        # Format the full result as pretty JSON
        try:
            # Remove some fields to avoid clutter
            display_result = result.copy()
            if "component_results" in display_result:
                # Keep only the most relevant parts of component results
                for component, data in display_result["component_results"].items():
                    if component == "llm" and "similar_examples" in data:
                        # Limit the number of similar examples shown
                        data["similar_examples"] = data["similar_examples"][:2]
            
            # Convert to pretty JSON
            details = json.dumps(display_result, indent=2, default=str)
            self.details_text.insert(tk.END, details)
        except Exception as e:
            self.details_text.insert(tk.END, f"Error formatting details: {str(e)}")
        
        self.details_text.config(state=tk.DISABLED)
    
    def _handle_analysis_error(self, error_message):
        """Handle errors during analysis"""
        # Enable buttons
        self.analyze_button.config(state=tk.NORMAL)
        self.load_button.config(state=tk.NORMAL)
        
        # Update status
        self.status_label.config(text=f"Error during analysis: {error_message}")
        
        # Show error message
        messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{error_message}")
    
    def _load_from_file(self):
        """Load email content from a file"""
        if not self.detector_ready:
            messagebox.showerror("Not Ready", "The phishing detection engine is not ready yet. Please wait.")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Text Files", "*.txt"), ("Email Files", "*.eml"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
            
            # Extract sender, recipient, subject from headers if possible
            sender = ""
            recipient = ""
            subject = ""
            body = email_content
            
            # Try to extract headers
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
            if sender_match:
                sender = sender_match.group(1).strip()
            
            to_match = re.search(r'To:\s*<?([^>\n]+)>?', email_content)
            if to_match:
                recipient = to_match.group(1).strip()
            
            subject_match = re.search(r'Subject:\s*([^\n]+)', email_content)
            if subject_match:
                subject = subject_match.group(1).strip()
            
            # Split headers and body
            parts = email_content.split("\n\n", 1)
            if len(parts) > 1:
                body = parts[1]
            
            # Update the UI fields
            self.sender_entry.delete(0, tk.END)
            self.sender_entry.insert(0, sender)
            
            self.recipient_entry.delete(0, tk.END)
            self.recipient_entry.insert(0, recipient)
            
            self.subject_entry.delete(0, tk.END)
            self.subject_entry.insert(0, subject)
            
            self.body_text.delete("1.0", tk.END)
            self.body_text.insert(tk.END, body)
            
            # Update status
            self.status_label.config(text=f"Loaded email from {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("File Error", f"Error loading file: {str(e)}")
    
    def _clear_fields(self):
        """Clear all input fields"""
        self.sender_entry.delete(0, tk.END)
        self.recipient_entry.delete(0, tk.END)
        self.subject_entry.delete(0, tk.END)
        self.body_text.delete("1.0", tk.END)
        
        # Clear results
        self.verdict_label.config(text="")
        self.confidence_label.config(text="")
        self.risk_progress["value"] = 0
        self.risk_text.config(text="")
        
        # Clear text areas
        for text_widget in [self.summary_text, self.suspicious_text, self.recommendations_text, self.details_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete("1.0", tk.END)
            text_widget.config(state=tk.DISABLED)
        
        # Update status
        self.status_label.config(text="Fields cleared")

    def _setup_menu(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Email (Ctrl+O)", command=self._load_from_file)
        file_menu.add_command(label="Clear Fields (Ctrl+N)", command=self._clear_fields)
        file_menu.add_separator()
        file_menu.add_command(label="Exit (Ctrl+Q)", command=self.root.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme (Ctrl+T)", command=self._toggle_theme)
        
        # History menu
        history_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="History", menu=history_menu)
        history_menu.add_command(label="View Analysis History (Ctrl+H)", command=self._show_history)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About (F1)", command=self._show_about)
        help_menu.add_command(label="Documentation (F2)", command=self._show_docs)
        
        # Add keyboard shortcuts
        self.root.bind("<Control-o>", lambda e: self._load_from_file())
        self.root.bind("<Control-n>", lambda e: self._clear_fields())
        self.root.bind("<Control-q>", lambda e: self.root.quit())
        self.root.bind("<Control-t>", lambda e: self._toggle_theme())
        self.root.bind("<Control-h>", lambda e: self._show_history())
        self.root.bind("<F1>", lambda e: self._show_about())
        self.root.bind("<F2>", lambda e: self._show_docs())
        self.root.bind("<F5>", lambda e: self._analyze_email())

    def _toggle_theme(self):
        """Toggle between light and dark theme"""
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self._setup_styles()
        
        # Save theme preference
        if not os.path.exists("phishing_detector_config.json"):
            self.config = {"ui_settings": {}}
        
        self.config["ui_settings"]["theme"] = self.current_theme
        with open("phishing_detector_config.json", "w") as f:
            json.dump(self.config, f, indent=4)

    def _show_loading(self):
        """Show the loading indicator"""
        self.loading_frame.pack(fill=tk.X, pady=10)
        self.loading_label.pack(pady=(0, 5))
        self.loading_progress.pack(fill=tk.X, padx=50)
        self.loading_progress.start(10)
        self.root.update()

    def _hide_loading(self):
        """Hide the loading indicator"""
        self.loading_progress.stop()
        self.loading_frame.pack_forget()
        self.root.update()

    def _show_history(self):
        """Show analysis history window"""
        history_window = tk.Toplevel(self.root)
        history_window.title("Analysis History")
        history_window.geometry("800x600")
        
        # Create history view
        history_frame = ttk.Frame(history_window, padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add history table
        columns = ("Date", "Sender", "Subject", "Risk Score", "Verdict")
        history_tree = ttk.Treeview(history_frame, columns=columns, show="headings")
        
        # Configure columns
        for col in columns:
            history_tree.heading(col, text=col)
            history_tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=history_tree.yview)
        history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load history data
        self._load_history_data(history_tree)

    def _load_history_data(self, tree):
        """Load history data into the tree view"""
        try:
            with open("email_history.csv", 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith("date"):
                        date, sender, subject, score, verdict = line.strip().split(',')
                        tree.insert("", tk.END, values=(date, sender, subject, score, verdict))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load history: {str(e)}")

    def _create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def show_tooltip(event):
            x = event.x_root + 10
            y = event.y_root + 10
            
            # Create tooltip window
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{x}+{y}")
            
            # Create tooltip content
            label = ttk.Label(tooltip, text=text, justify=tk.LEFT,
                            background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                            padding=5)
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            widget.tooltip = tooltip
            widget.after(2000, hide_tooltip)
        
        def hide_tooltip(event):
            if hasattr(widget, "tooltip"):
                widget.tooltip.destroy()
                del widget.tooltip
        
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)

    def _show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About PhishSentinel",
            "PhishSentinel - Advanced Phishing Detection\n\n"
            "Version: 1.0\n"
            "A sophisticated email analysis tool to detect phishing attempts\n"
            "using advanced machine learning techniques."
        )
    
    def _show_docs(self):
        """Show documentation"""
        messagebox.showinfo(
            "Documentation",
            "Documentation can be found in the README.md file\n"
            "and the project documentation folder."
        )

def main():
    """Main function to start the application"""
    root = tk.Tk()
    app = EnhancedPhishingDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 