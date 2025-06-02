import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, scrolledtext
from PIL import Image, ImageTk, ImageDraw # Import ImageDraw for placeholder
import smtplib
import ssl
import random
import string
import webbrowser
import os
import datetime
import cv2
import winreg
import subprocess # Used for is_admin check on Windows
import sys # For sys.executable and sys.argv
import ctypes # Import ctypes for administrator checks

# --- Global Variables ---
# These variables will store user-configured email settings.
# They are initialized as empty and populated via the 'Configure Email' menu option.
EMAIL_SENDER = ""
EMAIL_PASSWORD = "" # This should be an app-specific password, not your main email password.
# Updated to a list of recipient emails as requested.
EMAIL_RECEIVER = ["eswardhoni99@gmail.com", "harshaalla7@gmail.com", "yuvaraju.oggu@gmail.com"]
OTP_CODE = "" # Stores the currently generated One-Time Password for verification.

# File paths for logs and intruder videos.
LOG_FILE = "usb_security_log.txt"
INTRUDER_VIDEO_DIR = "intruder_videos"

# Root Tkinter window and USB status label, declared globally for easy access.
root = None
usb_status_label = None
pendrive_photo = None # To hold the PhotoImage object for the pendrive picture.

# --- Helper Function to Check Administrator Privileges (Windows Specific) ---
def is_admin():
    """
    Checks if the current script is running with administrator privileges.
    This is crucial for modifying system-level settings like USB port status.
    """
    try:
        # For Windows, use ctypes to check if the user is an administrator.
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        # If ctypes fails or not on Windows, assume not admin.
        # This function is primarily for Windows, so other OS checks are omitted for simplicity.
        return False

def run_as_admin():
    """
    Attempts to re-run the current script with administrator privileges on Windows.
    """
    if sys.platform == "win32":
        try:
            # Get the absolute path of the current script.
            # sys.argv[0] gives the script path, os.path.abspath converts it to an absolute path.
            script_path = os.path.abspath(sys.argv[0])
            # Quote the script path to handle spaces in the path, which can cause issues with ShellExecuteW.
            quoted_script_path = f'"{script_path}"'
            
            # Use ShellExecuteW to re-launch the script with 'runas' verb (administrator).
            # None: handle to the parent window (no parent here).
            # "runas": the operation to perform, which requests elevation.
            # sys.executable: the program to execute (the Python interpreter).
            # quoted_script_path: arguments passed to the executable (the script itself).
            # None: working directory (defaults to current).
            # 1: how the window is to be shown (SW_SHOWNORMAL).
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, quoted_script_path, None, 1
            )
            sys.exit(0) # Exit the current non-elevated process immediately.
        except Exception as e:
            # If elevation fails, display an error message and exit.
            messagebox.showerror("Error", f"Failed to restart as administrator: {e}")
            sys.exit(1) # Exit with an error code.
    else:
        # Inform the user if running on a non-Windows platform.
        messagebox.showwarning("Platform Not Supported", "Automatic administrator elevation is only supported on Windows.")

# --- Functions for USB Control (Windows Specific) ---
def set_usb_registry_status(enable):
    """
    Modifies the Windows Registry to enable or disable USB mass storage devices.
    This function requires administrator privileges.
    It targets the 'USBSTOR' service, which handles Plug and Play for USB storage.

    Args:
        enable (bool): True to enable USB mass storage, False to disable.
    Returns:
        bool: True if the registry modification was successful, False otherwise.
    """
    # Corrected path: 'CurrentControlSet' instead of 'CurrentSet'
    key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
    try:
        # Open the registry key with write access (KEY_SET_VALUE) and read access (KEY_READ).
        # HKEY_LOCAL_MACHINE stores system-wide settings.
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
        if enable:
            # Set 'Start' value to 3 (SYSTEM_START) to enable the service.
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
            messagebox.showinfo("USB Control", "Attempting to enable USB mass storage. You might need to restart your computer or replug devices for changes to take full effect.")
        else:
            # Set 'Start' value to 4 (DISABLED) to disable the service.
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
            messagebox.showinfo("USB Control", "Attempting to disable USB mass storage. Existing connected devices might still work until replugged or system restart.")
        winreg.CloseKey(key) # Always close the opened registry key.
        return True
    except PermissionError:
        # Catch PermissionError if the app is not run as administrator.
        messagebox.showerror("Permission Denied", "Administrator privileges are required to modify USB port status. Please run the application as administrator.")
        return False
    except Exception as e:
        # Catch any other exceptions during registry modification.
        messagebox.showerror("Error", f"Failed to change USB status: {e}")
        return False

def get_usb_registry_status():
    """
    Reads the current 'Start' value of the USBSTOR service from the Windows Registry
    to determine the USB mass storage status.

    Returns:
        str: "Enabled", "Disabled", "Unknown", or an error message if access fails.
    """
    # Corrected path: 'CurrentControlSet' instead of 'CurrentSet'
    key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
    try:
        # Open the registry key with read access.
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        start_value, _ = winreg.QueryValueEx(key, "Start") # Get the 'Start' value.
        winreg.CloseKey(key) # Close the key.
        if start_value == 3:
            return "Enabled"
        elif start_value == 4:
            return "Disabled"
        else:
            return "Unknown" # For any other unexpected 'Start' value.
    except FileNotFoundError:
        return "Not Found (USBSTOR service key missing)"
    except PermissionError:
        return "Permission Denied (Run as Admin for status)" # If status cannot be read due to permissions.
    except Exception as e:
        return f"Error: {e}"

# --- Functions for Email ---
def generate_otp():
    """
    Generates a random 8-character One-Time Password (OTP).
    The OTP consists of a mix of uppercase letters, lowercase letters, and digits.
    """
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(8))

def send_email(recipient_emails, otp_code):
    """
    Sends an email containing the generated OTP to the specified recipient(s).
    Requires sender email and app password to be configured in the application.

    Args:
        recipient_emails (list): A list of email addresses to which the OTP will be sent.
        otp_code (str): The One-Time Password to be sent.
    Returns:
        bool: True if the email was sent successfully to at least one recipient, False otherwise.
    """
    global EMAIL_SENDER, EMAIL_PASSWORD

    # Check if sender email credentials are configured.
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        messagebox.showerror("Email Configuration Error",
                             "Sender Email and App Password are not set. "
                             "Please go to File -> Configure Email to set them.")
        return False

    if not recipient_emails:
        messagebox.showerror("Email Error", "No recipient emails are set.")
        return False

    smtp_server = "smtp.gmail.com" # Default SMTP server for Gmail.
    port = 587  # Standard port for TLS (StartTLS).

    # Construct the email message.
    message = f"""\
Subject: Your USB Security App OTP

Your One-Time Password (OTP) for USB Security App is: {otp_code}

This password is valid for a single use.
"""
    context = ssl.create_default_context()
    success_count = 0
    failed_recipients = []

    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)

            for recipient in recipient_emails:
                try:
                    server.sendmail(EMAIL_SENDER, recipient, message)
                    success_count += 1
                except Exception as e:
                    failed_recipients.append(f"{recipient} ({e})")
                    print(f"Failed to send email to {recipient}: {e}") # Print to console for debugging

        if success_count > 0:
            if len(failed_recipients) == 0:
                messagebox.showinfo("Email Sent", f"OTP sent to all {success_count} recipients.")
            else:
                messagebox.showwarning("Email Sent with Warnings",
                                       f"OTP sent to {success_count} recipients. "
                                       f"Failed for: {', '.join(failed_recipients)}")
            return True
        else:
            messagebox.showerror("Email Error", f"Failed to send OTP to any recipient. Details: {', '.join(failed_recipients)}")
            return False
    except smtplib.SMTPAuthenticationError:
        messagebox.showerror("Email Error", "Failed to authenticate with email server. Check your sender email and app password.")
        return False
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to connect to email server: {e}")
        return False

# --- Functions for Webcam ---
def record_intruder_video():
    """
    Records a 5-second video from the default webcam.
    This function is called when an incorrect password is entered,
    acting as an intruder detection mechanism.
    The video is saved to the 'intruder_videos' directory.
    """
    # Create the directory for intruder videos if it doesn't exist.
    if not os.path.exists(INTRUDER_VIDEO_DIR):
        os.makedirs(INTRUDER_VIDEO_DIR)

    # Generate a unique filename for the video based on the current timestamp.
    file_name = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "_intruder.avi"
    output_path = os.path.join(INTRUDER_VIDEO_DIR, file_name)

    cap = cv2.VideoCapture(0) # Initialize video capture object (0 for default webcam).

    # Check if the webcam was opened successfully.
    if not cap.isOpened():
        messagebox.showerror("Webcam Error", "Could not open webcam. Please ensure it's connected and not in use by another application.")
        return

    # Get frame dimensions and frames per second (FPS) from the webcam.
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS) or 20 # Default to 20 FPS if webcam doesn't report it.

    # Define the video codec and create a VideoWriter object.
    # 'MJPG' is a common codec for AVI files that works well on Windows.
    fourcc = cv2.VideoWriter_fourcc(*'MJPG')
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))

    start_time = datetime.datetime.now()
    duration = 5 # Recording duration in seconds.

    # Display a non-blocking Toplevel window to inform the user about recording.
    recording_status_window = Toplevel(root)
    recording_status_window.title("Recording Intruder")
    recording_status_window.geometry("300x100")
    recording_status_window.transient(root) # Make it appear on top of the main window.
    recording_status_window.grab_set() # Disable interaction with the main window during recording.
    tk.Label(recording_status_window, text=f"Recording 5 seconds of video to:\n{output_path}", wraplength=280).pack(pady=10)
    recording_status_window.update_idletasks() # Force GUI update.

    # Loop to capture and write frames.
    while(True):
        ret, frame = cap.read() # Read a frame from the webcam.
        if ret:
            out.write(frame) # Write the frame to the output video file.
            # Check if the desired recording duration has passed.
            if (datetime.datetime.now() - start_time).total_seconds() >= duration:
                break
        else:
            messagebox.showerror("Webcam Error", "Failed to read frame from webcam during recording.")
            break

    # Release the webcam and video writer resources.
    cap.release()
    out.release()
    cv2.destroyAllWindows() # Close any OpenCV windows that might have been opened.
    recording_status_window.destroy() # Close the recording status window.
    messagebox.showinfo("Intruder Alert", f"Intruder video saved to {output_path}")

# --- Functions for Logging ---
def log_action(action_type, success):
    """
    Records an action (Enable/Disable USB) and its success status to a log file.

    Args:
        action_type (str): Description of the action (e.g., "Enable USB", "Disable USB").
        success (bool): True if the action was successful, False otherwise.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"
    log_entry = f"[{timestamp}] Action: {action_type}, Status: {status}\n"
    try:
        with open(LOG_FILE, "a") as f: # Open log file in append mode.
            f.write(log_entry)
    except Exception as e:
        messagebox.showerror("Log Error", f"Failed to write to log file: {e}")

def read_logs():
    """
    Reads and returns the entire content of the activity log file.

    Returns:
        str: The content of the log file, or a message if no logs are available/error occurs.
    """
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                return f.read()
        else:
            return "No logs available yet."
    except Exception as e:
        return f"Error reading logs: {e}"

# --- GUI Update Functions ---
def update_usb_status_display():
    """
    Updates the USB status label in the GUI by checking the current registry status.
    This function is called periodically to keep the status display up-to-date.
    """
    status = get_usb_registry_status()
    usb_status_label.config(text=f"USB Mass Storage Status: {status}")
    # Schedule the next update after 5000 milliseconds (5 seconds).
    root.after(5000, update_usb_status_display)

def show_project_info():
    """
    Opens a new browser tab displaying project details.
    The details are embedded in an HTML string, saved to a temporary file,
    and then opened using the default web browser.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>USB Physical Security Project Info</title>
        <style>
            body { font-family: 'Inter', sans-serif; margin: 20px; background-color: #f0f2f5; color: #333; line-height: 1.6; }
            h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            h2 { color: #34495e; margin-top: 25px; }
            ul { list-style-type: disc; margin-left: 20px; }
            li { margin-bottom: 5px; }
            .container { max-width: 800px; margin: auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
            .note { background-color: #e7f3fe; border-left: 6px solid #2196F3; padding: 10px; margin-top: 20px; border-radius: 4px; }
            .note strong { color: #2196F3; }
        </style>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1>USB Physical Security Application</h1>
            <p>This application provides a basic layer of physical security for your computer's USB ports, primarily focusing on USB mass storage devices.</p>

            <h2>Key Features:</h2>
            <ul>
                <li><strong>USB Port Control:</strong> Enable or disable USB mass storage functionality on your Windows system.</li>
                <li><strong>Password Protection:</strong> Critical actions (enable/disable) require a one-time password (OTP) sent to your registered email address.</li>
                <li><strong>Activity Logging:</strong> All enable/disable actions are logged with timestamps and success status.</li>
                <li><strong>Real-time Status:</strong> View the current status of USB mass storage (enabled/disabled).</li>
                <li><strong>Intruder Detection:</b> In case of an incorrect password attempt, the application can record a short video using your webcam.</li>
            </ul>

            <h2>How it Works:</h2>
            <p>The application interacts with the Windows Registry to modify the 'Start' value of the <code>USBSTOR</code> service. This service controls the Plug and Play functionality for USB mass storage devices.</p>
            <ul>
                <li>Setting 'Start' to <code>4</code> effectively disables the service, preventing new USB drives from being recognized.</li>
                <li>Setting 'Start' to <code>3</code> re-enables the service.</li>
            </ul>

            <div class="note">
                <strong>Important Note:</strong>
                <p>This application primarily affects <strong>newly connected USB mass storage devices</strong> (like pendrives, external hard drives). It does not typically disable existing connected devices, USB keyboards, mice, or webcams. For a more comprehensive disable of all USB functionality, advanced system tools (like Microsoft's DevCon utility) would be required, which is beyond the scope of this self-contained Python application.</p>
                <p><strong>Administrator privileges are required</strong> to run this application and modify USB settings.</p>
                <p>For email functionality, if you are using Gmail, you will need to generate an "App password" instead of using your regular Gmail password. Refer to Google's documentation on "App passwords" for more details.</p>
            </div>

            <h2>Developed By:</h2>
            <p>Your Name / Project Team</p>
            <p>Date: June 2025</p>
        </div>
    </body>
    </html>
    """
    temp_html_file = "project_info.html"
    try:
        with open(temp_html_file, "w") as f:
            f.write(html_content)
        # Open the generated HTML file in a new browser tab.
        webbrowser.open_new_tab(f"file:///{os.path.abspath(temp_html_file)}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open project info: {e}")

def configure_email_settings():
    """
    Prompts the user to input their sender email and app password.
    The recipient emails are now hardcoded as per the request.
    """
    global EMAIL_SENDER, EMAIL_PASSWORD
    sender = simpledialog.askstring("Email Configuration", "Enter Sender Email (e.g., your_email@gmail.com):", initialvalue=EMAIL_SENDER)
    if sender:
        password = simpledialog.askstring("Email Configuration", "Enter Sender App Password (NOT your main email password):", show='*', initialvalue=EMAIL_PASSWORD)
        if password:
            EMAIL_SENDER = sender
            EMAIL_PASSWORD = password
            messagebox.showinfo("Email Configuration", "Sender email settings saved successfully. OTPs will be sent to the pre-configured recipient list.")
        else:
            messagebox.showwarning("Email Configuration", "App password cannot be empty.")
    else:
        messagebox.showwarning("Email Configuration", "Sender email cannot be empty.")

def prompt_for_password(action_type):
    """
    Generates an OTP, sends it to the configured recipient emails,
    and then prompts the user to enter the received password.
    If the password is incorrect, it triggers the intruder webcam recording.

    Args:
        action_type (str): The action being performed (e.g., "Enable USB", "Disable USB").
    Returns:
        bool: True if the entered password is correct, False otherwise.
    """
    global OTP_CODE, EMAIL_RECEIVER
    OTP_CODE = generate_otp() # Generate a new OTP for each action.

    # Pass the list of recipient emails to send_email
    if not send_email(EMAIL_RECEIVER, OTP_CODE):
        messagebox.showerror("Action Failed", "Could not send OTP. Please check email configuration and try again.")
        return False

    # Create a Toplevel window for password input.
    password_window = Toplevel(root)
    password_window.title(f"Enter Password for {action_type}")
    password_window.geometry("350x150")
    password_window.transient(root) # Make it appear on top of the main window.
    password_window.grab_set() # Disable interaction with the main window until this window is closed.

    # Display the recipient emails for clarity.
    recipient_display_text = ", ".join(EMAIL_RECEIVER)
    tk.Label(password_window, text=f"An OTP has been sent to:\n{recipient_display_text}\nPlease enter it below:").pack(pady=10)
    password_entry = tk.Entry(password_window, show='*', width=30) # Password entry with hidden characters.
    password_entry.pack(pady=5)
    password_entry.focus_set() # Set focus to the entry field.

    result = tk.BooleanVar(value=False) # Variable to store the verification result.

    def verify_password():
        """
        Internal function to verify the entered password against the generated OTP.
        """
        entered_password = password_entry.get()
        if entered_password == OTP_CODE:
            result.set(True) # Set result to True on success.
            password_window.destroy() # Close the password window.
        else:
            messagebox.showerror("Incorrect Password", "The password you entered is incorrect.")
            record_intruder_video() # Trigger webcam recording on incorrect password.
            result.set(False) # Ensure result is False on incorrect password.

    tk.Button(password_window, text="Verify", command=verify_password).pack(pady=10)

    root.wait_window(password_window) # Wait for the password window to be closed by user or verification.
    return result.get() # Return the verification result.

# --- Event Handlers for Buttons ---
def on_enable_usb():
    """
    Handles the 'Enable USB' button click.
    Prompts for password, then attempts to enable USB mass storage if password is correct.
    Logs the action and updates the USB status display.
    """
    if prompt_for_password("Enable USB"):
        success = set_usb_registry_status(True)
        log_action("Enable USB", success)
        update_usb_status_display()

def on_disable_usb():
    """
    Handles the 'Disable USB' button click.
    Prompts for password, then attempts to disable USB mass storage if password is correct.
    Logs the action and updates the USB status display.
    """
    if prompt_for_password("Disable USB"):
        success = set_usb_registry_status(False)
        log_action("Disable USB", success)
        update_usb_status_display()

def on_view_logs():
    """
    Handles the 'View Activity Logs' button click.
    Opens a new Toplevel window displaying the contents of the activity log file.
    """
    log_window = Toplevel(root)
    log_window.title("Activity Logs")
    log_window.geometry("600x400")
    log_window.transient(root)
    log_window.grab_set()

    log_text_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=70, height=20)
    log_text_area.pack(expand=True, fill="both", padx=10, pady=10)
    log_text_area.insert(tk.END, read_logs()) # Insert log content.
    log_text_area.config(state=tk.DISABLED) # Make the text area read-only.

    tk.Button(log_window, text="Close", command=log_window.destroy).pack(pady=5)

# --- Main Application Setup ---
def main():
    """
    Sets up the main Tkinter application window, UI elements, and initial state.
    """
    global root, usb_status_label, pendrive_photo

    root = tk.Tk()
    root.title("USB Physical Security App")
    root.geometry("400x600") # Fixed window size for consistent layout.
    root.resizable(False, False) # Prevent resizing.

    # --- Menu Bar ---
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Configure Email", command=configure_email_settings)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    # --- Pendrive Image Display ---
    try:
        # Placeholder image for a pendrive.
        img = Image.new('RGB', (200, 150), color = '#ADD8E6') # Light blue background
        d = ImageDraw.Draw(img)
        # Try to load a default font, fallback to None if not found
        try:
            from PIL import ImageFont
            font = ImageFont.truetype("arial.ttf", 15)
        except (ImportError, IOError): # IOError for font not found
            font = None
            messagebox.showwarning("Font Warning", "arial.ttf not found for image text. Using default font.")

        d.rectangle([50, 50, 150, 100], fill='#87CEEB', outline='black') # Body
        d.rectangle([130, 60, 170, 90], fill='#6A5ACD', outline='black') # Cap
        d.text((55, 65), "USB Drive", fill=(0,0,0), font=font) # Text
        pendrive_photo = ImageTk.PhotoImage(img)

    except Exception as e:
        messagebox.showwarning("Image Error", f"Could not create pendrive image placeholder. Error: {e}")
        # Fallback to a simpler placeholder if the above fails (e.g., missing font).
        img = Image.new('RGB', (200, 150), color = 'lightgray')
        d = ImageDraw.Draw(img)
        d.text((50, 60), "Pendrive Image", fill=(0,0,0))
        pendrive_photo = ImageTk.PhotoImage(img)

    pendrive_label = tk.Label(root, image=pendrive_photo)
    pendrive_label.pack(pady=20)

    # --- USB Status Display ---
    usb_status_label = tk.Label(root, text="USB Mass Storage Status: Checking...", font=("Arial", 12, "bold"), fg="#333")
    usb_status_label.pack(pady=10)
    update_usb_status_display() # Call once to set initial status and start periodic updates.

    # --- Action Buttons ---
    button_frame = tk.Frame(root)
    button_frame.pack(pady=20)

    enable_button = tk.Button(button_frame, text="Enable USB", command=on_enable_usb,
                              width=15, height=2, bg="#4CAF50", fg="white",
                              font=("Arial", 10, "bold"), relief=tk.RAISED, bd=3, cursor="hand2")
    enable_button.pack(side=tk.LEFT, padx=10)

    disable_button = tk.Button(button_frame, text="Disable USB", command=on_disable_usb,
                               width=15, height=2, bg="#F44336", fg="white",
                               font=("Arial", 10, "bold"), relief=tk.RAISED, bd=3, cursor="hand2")
    disable_button.pack(side=tk.RIGHT, padx=10)

    # --- Additional Functionality Buttons ---
    project_info_button = tk.Button(root, text="Project Info", command=show_project_info,
                                    width=30, height=2, bg="#2196F3", fg="white",
                                    font=("Arial", 10, "bold"), relief=tk.RAISED, bd=3, cursor="hand2")
    project_info_button.pack(pady=10)

    view_logs_button = tk.Button(root, text="View Activity Logs", command=on_view_logs,
                                 width=30, height=2, bg="#FFC107", fg="black",
                                 font=("Arial", 10, "bold"), relief=tk.RAISED, bd=3, cursor="hand2")
    view_logs_button.pack(pady=10)

    root.mainloop() 
    # Start the Tkinter event loop.
    

if __name__ == "__main__":
    # Check for administrator privileges and re-run if necessary.
    if not is_admin():
        run_as_admin()
        # The script will exit here if re-launched as admin, so no further code runs in this instance.

    # Ensure necessary PIL modules are imported before main is called.
    try:
        from PIL import ImageDraw # ImageDraw is always needed for drawing on images
    except ImportError:
        messagebox.showerror("Error", "Pillow library (ImageDraw) not found. Please install it using 'pip install Pillow'.")
        sys.exit(1) # Exit with an error code.

    # Check for pywin32 and opencv-python as they are core dependencies.
    try:
        import winreg
    except ImportError:
        messagebox.showerror("Error", "pywin32 library not found. Please install it using 'pip install pywin32'.")
        sys.exit(1) # Exit with an error code.
    try:
        import cv2
    except ImportError:
        messagebox.showerror("Error", "opencv-python library not found. Please install it using 'pip install opencv-python'.")
        sys.exit(1) # Exit with an error code.

    main()