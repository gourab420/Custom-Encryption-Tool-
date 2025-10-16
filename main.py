import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from PyPDF2 import PdfReader, PdfWriter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

#key padding
def pad_key(key,length):
    return key.ljust(length,b'\0')

#message length
def msg_len(msg):
    if len(msg)<=16:
        return 16
    elif len(msg)<=24:
        return 24
    else:
        return 32
    
#aes encryption
def encrypt(message,key):
    cipher=AES.new(key,AES.MODE_EAX)
    nonce=cipher.nonce
    ciphertext,tag=cipher.encrypt_and_digest(message.encode('ascii'))
    return nonce,ciphertext,tag

#aes decryption
def decrypt(nonce,ciphertext,tag,key):
    try:
        cipher=AES.new(key,AES.MODE_EAX,nonce=nonce)
        pt=cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return pt.decode('ascii')
    except Exception as e:
        return "decryption failed"
    
#railfrance encryption   
def rail_encryp(mess):
    mess=mess.replace(" ","0")
    if len(mess)%2!=0:
        mess=mess+'0'
    lst1=""
    lst2=""
    j=0
    for i in mess:
        if j%2==0:
            lst1=lst1+i
            j+=1
        else:
            lst2=lst2+i
            j+=1
    lst3=lst1+lst2
    return lst3

#railfrance decryption 
def rail_decryp(mess):
    l=int(len(mess)/2)
    tm1=mess[:l]
    tm2=mess[l:]
    result=""
    for i in range(int(len(mess)/2)):
        result=result+tm1[i]
        result=result+tm2[i]
    result=result.replace("0"," ")
    return result

#extract text from pdf
def extract_pdf_text(pdf_path):
    try:
        reader=PdfReader(pdf_path)
        text=""
        for page in reader.pages:
            text+=page.extract_text() 
        return text.strip() 
    except Exception as e:
        messagebox.showerror("error","failed to read pdf")
        return None

#new pdf with encrypted text
def save_encrypted_pdf(original_pdf_path,ciphertext):
    output_pdf_path=original_pdf_path.replace(".pdf", "_new_enptd.pdf")
    
    c=canvas.Canvas(output_pdf_path,pagesize=letter)
    lines=[ciphertext[i:i+90] for i in range(0,len(ciphertext),90)]  # Split ciphertext into lines  
    for i, line in enumerate(lines):
        c.drawString(40,750 - (i * 12),line)  # Write each line to the PDF      
    c.save()

#pdf choose
def browse_pdf():
    file_path=filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    pdf_path.set(file_path)

    if file_path:
        pdf_text=extract_pdf_text(file_path)
        if pdf_text:
            manual_text.delete(1.0,tk.END)
            manual_text.insert(tk.END,pdf_text)
            
#encryption button
def en_data():
    m=manual_text.get("1.0",tk.END).strip()
    key_input=key_entry.get().encode('ascii')
    if not m:
        messagebox.showerror("message box is empty")
        return
    if not key_input:
        messagebox.showerror("provide a key")
        return
    message=rail_encryp(m)
    key_length=msg_len(message)
    key=pad_key(key_input,key_length)

    try:
        global stored_nonce,stored_tag,stored_ciphertext  
        nonce,ciphertext,tag=encrypt(message,key)
        stored_nonce,stored_tag,stored_ciphertext=nonce,tag,ciphertext
        output_text.set(ciphertext.hex())
        
        if len(pdf_path.get())>0:
            save_encrypted_pdf(pdf_path.get(),ciphertext.hex())       
        messagebox.showinfo("encryption","message encryption successfully.")
    except Exception as e:
        messagebox.showerror("failed encryption")

#decryption button
def decrypt_data():
    ciphertext_hex=manual_text.get("1.0",tk.END).strip()
    key_input=key_entry.get().encode('ascii')

    if not ciphertext_hex:
        messagebox.showerror("message box is empty")
        return
    if not key_input:
        messagebox.showerror("provide a key")
        return
    try:
        ciphertext=bytes.fromhex(ciphertext_hex)
        key_length=msg_len(ciphertext) 
        key=pad_key(key_input, key_length)
        p=decrypt(stored_nonce,ciphertext,stored_tag,key)
        plaintext=rail_decryp(p)
        output_text.set(plaintext)
        if plaintext:
            messagebox.showinfo("decryption","message decryption successfully.")
        else:
            messagebox.showerror("error","decryption failed!")
    except Exception as e:
        messagebox.showerror("decryption failed")

def clear_all():
    pdf_path.set("")
    manual_text.delete(1.0, tk.END)
    key_entry.delete(0, tk.END)
    output_text.set("")

#gui part
root=tk.Tk()
root.title("Custom AES Encryption Tool with Rail Fence Cipher")
root.geometry("600x500")

tk.Label(root,text="Manual Input Text:").pack(pady=5)
manual_text=tk.Text(root,height=3,width=50)
manual_text.pack(pady=5)

tk.Label(root,text="Upload a PDF File:").pack(pady=5)
pdf_path=tk.StringVar()
tk.Entry(root,textvariable=pdf_path,width=50,state="readonly").pack(pady=5)
tk.Button(root,text="Browse",command=browse_pdf).pack(pady=5)

tk.Label(root,text="Enter Key:").pack(pady=5)
key_entry=tk.Entry(root,width=50)
key_entry.pack(pady=5)

tk.Button(root,text="Encrypt",command=en_data).pack(pady=10)
tk.Button(root,text="Decrypt",command=decrypt_data).pack(pady=10)

output_text=tk.StringVar()
tk.Label(root,text="Output").pack(pady=5)
tk.Entry(root,textvariable=output_text,width=65,state="readonly").pack(pady=5)

tk.Button(root,text="Clear",command=clear_all).pack(pady=10)
root.mainloop()
