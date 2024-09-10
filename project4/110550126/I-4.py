#!/usr/bin/python3
import os
import pytesseract
from PIL import Image
file_name = "Matryoshka dolls.jpg"

def solve():
    
    if os.path.exists(file_name):
        print("Extracting the Matryoshka dolls.jpg")
        os.system(f"binwalk -e '{file_name}' -q")
    else:
        print("Matryoshka dolls.jpg not found")
        exit(1)
        
    extracted_dir = "_" + file_name + ".extracted"
    

    if os.path.exists(extracted_dir):
        source = os.path.join(extracted_dir, "flag.txt")
        destination = os.path.join(extracted_dir, "flag.jpg")
        os.system(f"cp '{source}' '{destination}'")
        img = Image.open(destination)
        text = pytesseract.image_to_string(img)
        print(text)
    else:
        print("Extracted directory not found")
        exit(1)
        
if __name__ == "__main__":
    solve()