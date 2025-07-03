# Nmap Dependency

🚨 **Important**: This project requires [Nmap](https://nmap.org/download.html) to perform certain network scans.

## How to install Nmap

1. **Go to the official download page**:  
   👉 https://nmap.org/download.html

2. **Download Nmap for your system** (e.g., `nmap-7.97-setup.exe` for Windows)

3. **Install Nmap** normally.

4. After installation, locate the Nmap folder:
   - For Windows, it is usually in:  
     `C:\Program Files (x86)\Nmap`

5. **Copy the entire contents** of that folder (not just `nmap.exe`) and place it here:

✅ After copying, you should see:
- `nmap.exe`
- `nmap-update.exe`
- `nmap-services`
- and other Nmap files.

---

## Why not include Nmap in the repo?

- Nmap is licensed under the [Nmap Public Source License](https://nmap.org/book/man-legal.html), which **does not allow redistribution of compiled binaries** without explicit permission.
- By instructing users to download from the official source, you comply with licensing and legal requirements.

---

## Automation (Optional)

If you'd like to **automatically detect if Nmap is missing**, your Python code will alert the user and point them to this folder. Example:

```python
nmap_path = os.path.join("external", "nmap", "nmap.exe")
if not os.path.exists(nmap_path):
 return "❌ Nmap not found. Please download Nmap and place it in 'external/nmap/'. See README in that folder."
