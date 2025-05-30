import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import webbrowser
import os

#pop ups
def register_user():
    popup=tk.Toplevel()
    popup.title("Registration page")
    popup.geometry("400x350")
    popup.configure(bg="black")

    tk.Label(popup,text="name:",fg="white",bg="black").pack(pady=5)
    entry_name=tk.Entry(popup,width=30)
    entry_name.pack(pady=10)

    tk.Label(popup,text="email",fg="white",bg="black").pack(pady=5)
    entry_email=tk.Entry(popup,width=30)
    entry_email.pack(pady=10)

    tk.Label(popup,text="password",fg="white",bg="black").pack(pady=5)
    entry_password=tk.Entry(popup,width=30,show=".")
    entry_password.pack(pady=10)

    def submit():
        name=entry_name.get()
        email=entry_email.get()
        password=entry_password.get()
        if name and email and password:
            messagebox.showinfo("successful","you have successfully registered")
            popup.destroy()
        else:
            messagebox.showinfo("failed","check the credentials")
    tk.Button(popup,text="submit",command=submit,bg="black",fg="white").pack(pady=5)

def show_info():
   html_path=os.path.abspath("projectinformation.html")
   webbrowser.open(f"file://{html_path}")

def disable_usb():
    popup=tk.Toplevel()
    popup.title("Authentication Required")
    popup.geometry("300x200")
    popup.configure(bg="black")

    tk.Label(popup, text="Enter Email:",fg="white",bg="black").pack(pady=5)
    email_entry = tk.Entry(popup,width=30)
    email_entry.insert(0,"Enter Email")
    email_entry.pack(pady=5)

    tk.Label(popup,text="Enter password:",fg="white",bg="black").pack(pady=5)
    password_entry = tk.Entry(popup, width=30, show="*")
    password_entry.insert(0, "Enter Password")
    password_entry.pack(pady=5)

    def submit():
        email =email_entry.get()
        password=password_entry.get()
        if email and password:
            messagebox.showinfo("Success", "USB ports disabled")
            popup.destroy()
        else:
            messagebox.showerror("failed Authentication","check the credentials")
    
    tk.Button(popup, text="submit", command=submit, bg="white", fg="black").pack(pady=10)

def enable_usb():
    popup = tk.Toplevel()
    popup.title("Authentication Required")
    popup.geometry("300x200")
    popup.configure(bg="black")

    tk.Label(popup, text="Enter Email:", fg="white", bg="black").pack(pady=5)
    email_entry = tk.Entry(popup, width=30)
    email_entry.insert(0, "Enter Email")
    email_entry.pack(pady=5)

    tk.Label(popup, text="Enter Password:", fg="white", bg="black").pack(pady=5)
    password_entry = tk.Entry(popup, width=30, show="*")
    password_entry.insert(0, "Enter Password")
    password_entry.pack(pady=5)

    def submit():
        email = email_entry.get()
        password = password_entry.get()
        if email and password:
            messagebox.showinfo("success","USB ports enabled")
            popup.destroy()
        else:
            messagebox.showerror("failed Authentication","check the credentials")

    tk.Button(popup, text="Submit", command=submit, bg="white", fg="black").pack(pady=10)

#mainfoot
root = tk.Tk()
root.title("USB Physical Security For Systems")
root.geometry("900x700")
root.configure(bg="black")

btn_info = tk.Button(root, text="Project Info", command=show_info,bg="white", fg="black", font=("Arial", 15, "bold"))
btn_info.pack(pady=20)

btn_register = tk.Button(root, text="Register", command=register_user,bg="white", fg="black", font=("Arial", 12, "bold"))
btn_register.place(x=550, y=20)


#labeling
label = tk.Label(root, text="USB Physical Security!!!", bg="black", fg="white", font=("Arial", 15, "bold"))
label.pack()

#image gui ki
img = Image.open("pendrive.jpg")
img = img.resize((250, 250))
photo = ImageTk.PhotoImage(img)
img_label = tk.Label(root, image=photo, bg="black")
img_label.pack(pady=10)

#buttons ki background
frame = tk.Frame(root, bg="black", width=300, height=200)
frame.pack(pady=20)

#frame loni buttons ki
btn_disable = tk.Button(frame, text="Disable USB", command=disable_usb,bg="white", fg="black", font=("Arial", 15, "bold"))
btn_disable.pack(pady=10)

btn_enable = tk.Button(frame, text="Enable USB", command=enable_usb,bg="white", fg="black", font=("Arial", 15, "bold"))
btn_enable.pack(pady=10)

root.mainloop()