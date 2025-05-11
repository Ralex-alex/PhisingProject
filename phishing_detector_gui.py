import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from PIL import Image, ImageTk
import os
import sys
import json
from combined_pipeline import PhishingDetectionPipeline

class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Detector")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)
        
        # Set app icon if available
        try:
            self.root.iconbitmap("shield_icon.ico")
        except:
            pass  # Icon not available, use default
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 12))
        self.style.configure("TLabel", font=("Arial", 12))
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        self.style.configure("Result.TLabel", font=("Arial", 14))
        self.style.configure("Safe.TLabel", foreground="green", font=("Arial", 16, "bold"))
        self.style.configure("Danger.TLabel", foreground="red", font=("Arial", 16, "bold"))
        
        # Create the model in a separate thread
        self.model = None
        self.model_ready = False
        self.loading_model = False
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add title
        title_label = ttk.Label(main_frame, text="Email Phishing Detector", style="Header.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Create input frame
        input_frame = ttk.LabelFrame(main_frame, text="Email Content", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Add subject field
        subject_frame = ttk.Frame(input_frame)
        subject_frame.pack(fill=tk.X, pady=(0, 5))
        
        subject_label = ttk.Label(subject_frame, text="Subject:")
        subject_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.subject_entry = ttk.Entry(subject_frame, width=50)
        self.subject_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add body field
        body_label = ttk.Label(input_frame, text="Email Body:")
        body_label.pack(anchor=tk.W, pady=(5, 5))
        
        self.body_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.body_text.pack(fill=tk.BOTH, expand=True)
        
        # Create buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Add analyze button
        self.analyze_button = ttk.Button(buttons_frame, text="Check Email", command=self.analyze_email)
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Add clear button
        clear_button = ttk.Button(buttons_frame, text="Clear", command=self.clear_fields)
        clear_button.pack(side=tk.LEFT)
        
        # Create result frame
        self.result_frame = ttk.LabelFrame(main_frame, text="Analysis Result", padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status label (initially hidden)
        self.status_label = ttk.Label(self.result_frame, text="", style="Result.TLabel")
        self.status_label.pack(pady=10)
        
        # Result label (initially hidden)
        self.result_label = ttk.Label(self.result_frame, text="", style="Result.TLabel")
        self.result_label.pack(pady=10)
        
        # Details frame
        self.details_frame = ttk.Frame(self.result_frame)
        self.details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Start loading the model in a background thread
        self.load_model_thread = threading.Thread(target=self.load_model)
        self.load_model_thread.daemon = True
        self.load_model_thread.start()
        
        # Show initial status
        self.status_label.config(text="Loading model... Please wait.")
        
        # Check model status periodically
        self.check_model_status()
    
    def load_model(self):
        """Load the phishing detection model in a background thread"""
        self.loading_model = True
        try:
            self.model = PhishingDetectionPipeline()
            
            # Check if model directory exists, if not, train a new model
            if not os.path.exists("models"):
                print("Training new model...")
                # Use a smaller dataset for faster training if available
                if os.path.exists("emails.csv"):
                    data_dict = self.model.prepare_data("emails.csv", test_size=0.3)
                else:
                    data_dict = self.model.prepare_data("emails_from_spamassassin.csv", test_size=0.3)
                self.model.train(data_dict)
                self.model.save()
            else:
                # Load existing model
                self.model.load()
            
            self.model_ready = True
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model_ready = False
        finally:
            self.loading_model = False
    
    def check_model_status(self):
        """Check if the model has finished loading"""
        if self.loading_model:
            # Still loading, check again later
            self.root.after(1000, self.check_model_status)
        elif self.model_ready:
            # Model loaded successfully
            self.status_label.config(text="Model loaded successfully. Ready to analyze emails.")
            self.analyze_button.config(state=tk.NORMAL)
        else:
            # Model failed to load
            self.status_label.config(text="Error loading model. Please restart the application.")
            self.analyze_button.config(state=tk.DISABLED)
    
    def analyze_email(self):
        """Analyze the email content for phishing indicators"""
        if not self.model_ready:
            messagebox.showerror("Model Not Ready", "The phishing detection model is not ready yet. Please wait.")
            return
        
        # Get email content
        subject = self.subject_entry.get().strip()
        body = self.body_text.get("1.0", tk.END).strip()
        
        if not body:
            messagebox.showerror("Missing Content", "Please enter the email body content.")
            return
        
        # Prepare the email text (combine subject and body)
        full_text = f"Subject: {subject}\n\n{body}"
        
        try:
            # Get model prediction
            predictions = self.model.predict([full_text])
            prediction = predictions[0]
            
            # Get probability scores
            X_tfidf = self.model.tfidf_vectorizer.transform([full_text])
            phishing_prob = self.model.nb_model.predict_proba(X_tfidf)[0][1]
            
            # Clear previous results
            for widget in self.details_frame.winfo_children():
                widget.destroy()
            
            # Update result labels
            if prediction == 1:  # Phishing
                self.result_label.config(
                    text="⚠️ PHISHING EMAIL DETECTED ⚠️", 
                    style="Danger.TLabel"
                )
                
                # Add warning details
                confidence = int(phishing_prob * 100)
                warning_text = f"Confidence: {confidence}%\n\nThis email contains suspicious elements typical of phishing attempts."
                warning_label = ttk.Label(self.details_frame, text=warning_text, wraplength=500)
                warning_label.pack(pady=10)
                
                # Add advice
                advice_text = "ADVICE: Do not click any links, do not download attachments, and do not reply to this email."
                advice_label = ttk.Label(self.details_frame, text=advice_text, wraplength=500)
                advice_label.pack(pady=10)
                
            else:  # Legitimate
                self.result_label.config(
                    text="✓ LEGITIMATE EMAIL", 
                    style="Safe.TLabel"
                )
                
                # Add confidence details
                confidence = int((1 - phishing_prob) * 100)
                safe_text = f"Confidence: {confidence}%\n\nNo suspicious elements detected in this email."
                safe_label = ttk.Label(self.details_frame, text=safe_text, wraplength=500)
                safe_label.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"An error occurred during analysis: {str(e)}")
    
    def clear_fields(self):
        """Clear all input fields"""
        self.subject_entry.delete(0, tk.END)
        self.body_text.delete("1.0", tk.END)
        
        # Clear results
        self.result_label.config(text="")
        for widget in self.details_frame.winfo_children():
            widget.destroy()

def main():
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main() 